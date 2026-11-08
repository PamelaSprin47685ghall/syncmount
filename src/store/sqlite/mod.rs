//! Shared SQLite state store for both ends of the sync.
//!
//! # Model
//!
//! The same core tables exist on the server and on every client:
//!
//! ```text
//! meta          key/value: epoch, seq, applied_seq, state_hash, ...
//! objects       one row per inode: kind, attrs, size, file_root, nlink
//! names         one row per directory entry: (parent, name) -> ino, path
//! chunks        content-addressed blocks: BLAKE3(data) -> data
//! object_chunks a file's ordered chunk list
//! events        the append-only operation log
//! ```
//!
//! The server treats `objects/names/object_chunks` as the authoritative state
//! and `events` as the increment. A client keeps the same tables as its
//! replica and adds `outbox`, `outbox_chunks`, `locks` and `fuse_inos`. The
//! server adds `op_ids` and `event_chunks`.
//!
//! # Concurrency
//!
//! One [`Db`] owns one connection and at most one writer. [`Db::write`] takes
//! `&mut Db` and opens `BEGIN IMMEDIATE`; Rust's borrow rules make a second
//! concurrent writer through the same handle unrepresentable. Readers use
//! [`Db::read`], which opens a deferred transaction and therefore sees a
//! consistent WAL snapshot while a writer is active.
//!
//! # What this module does not do
//!
//! It does not apply events to the object tree, does not run the outbox, and
//! does not choose a conflict policy. Those are the client and server layers.
//! This module owns the schema, the transaction shape, the sequence counter,
//! the event log, and the state digest.
//!
//! # Hashes
//!
//! [`hash::state_hash`] is the checkpoint digest. [`compact`] folds the event
//! log into a minimal, replayable description of the current tree without
//! touching the tree itself, so the digest is invariant across compaction.

mod event;
mod hash;
mod schema;
mod types;

#[cfg(test)]
mod tests;

pub use event::{
    EventDraft, EventKind, EventPayload, EventRow, InsertedEvent, MAX_PAYLOAD_BYTES,
    PAYLOAD_VERSION, PAYLOAD_VERSION_V1,
};
#[cfg(test)]
pub(crate) use event::V1_SETATTR_BYTES;
pub use hash::{chunk_hash, file_root};
pub use schema::{CHUNK_BYTES, ROOT_INO, ROOT_MODE, ROOT_NLINK, keys};
pub use types::{Chunk, ChunkRef, MetaValue, Name, Object, ObjectKind, OpId, RejectState};

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::types::Value;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use thiserror::Error;

/// Core schema version written to `PRAGMA user_version` and
/// `meta.schema_version`.
pub const SCHEMA_VERSION: i64 = 1;

/// First epoch of a fresh database.
pub const DEFAULT_EPOCH: i64 = 1;

/// Largest page [`ReadTx::events_from`] will return. A caller that asks for
/// more is clamped; a caller that asks for zero gets an empty page.
pub const MAX_EVENT_PAGE: u32 = 4096;

/// Result alias used across the store boundary.
pub type Result<T, E = StoreError> = std::result::Result<T, E>;

/// Which end of the sync owns this database.
///
/// The role is recorded in `meta.role` and checked on every open. Opening a
/// server database as a client (or the reverse) is a configuration error, not
/// something to repair silently.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    Client,
    Server,
}

impl Role {
    /// The exact text stored in `meta.role`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }

    /// Parse the `meta.role` text.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "client" => Some(Self::Client),
            "server" => Some(Self::Server),
            _ => None,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Everything this layer can refuse.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("schema version {found} is newer than supported {supported}")]
    UnsupportedSchema { found: i64, supported: i64 },

    #[error("chunk size is {stored}, this build supports {supported}")]
    ChunkSizeMismatch { stored: i64, supported: i64 },

    #[error("database belongs to role {stored}, opened as {requested}")]
    RoleMismatch { stored: Role, requested: Role },

    #[error("{operation} is not valid for the {role} role")]
    WrongRole { role: Role, operation: &'static str },

    #[error("meta key {0:?} is missing")]
    MissingMeta(String),

    #[error("meta key {key:?} is {actual}, expected {expected}")]
    MetaType {
        key: String,
        expected: &'static str,
        actual: &'static str,
    },

    #[error("event seq {seq} already exists")]
    DuplicateSeq { seq: i64 },

    #[error("op_id {} already exists at seq {existing}", hex::encode(.op_id))]
    DuplicateOp { op_id: [u8; 16], existing: i64 },

    #[error("epoch {requested} is stale; current epoch is {current}")]
    StaleEpoch { requested: i64, current: i64 },

    #[error("event payload codec: {0}")]
    Codec(String),

    #[error("event payload version {found} is not supported (current is {supported})")]
    PayloadVersion { found: u8, supported: u8 },

    #[error("event payload is {payload} but the row says {kind}")]
    PayloadKindMismatch {
        kind: &'static str,
        payload: &'static str,
    },

    #[error("invalid {kind} event: {reason}")]
    InvalidEvent {
        kind: &'static str,
        reason: &'static str,
    },

    #[error("invalid name: {0}")]
    InvalidName(&'static str),

    #[error("invalid path: {0}")]
    InvalidPath(&'static str),

    #[error("{field} value {value} is out of range")]
    OutOfRange { field: &'static str, value: i64 },

    #[error("chunk hash does not match its content")]
    ChunkHashMismatch,

    #[error("server chunks must carry data (hash {})", hex::encode(.hash))]
    ChunkDataRequired { hash: [u8; 32] },

    #[error("chunk {} declares {declared} bytes but carries {actual}", hex::encode(.hash))]
    ChunkLengthMismatch {
        hash: [u8; 32],
        declared: u32,
        actual: usize,
    },

    #[error("object_chunks for ino {} are not contiguous", hex::encode(.ino))]
    NonContiguousChunks { ino: [u8; 16] },

    #[error("chunk {chunk_no} has offset {offset}, expected {expected}")]
    ChunkOffsetMismatch {
        chunk_no: u32,
        offset: u64,
        expected: u64,
    },

    #[error("{kind} objects cannot be represented in the event log")]
    UnsupportedObject { kind: ObjectKind },

    #[error("journal mode is {mode:?}, expected WAL")]
    NotWal { mode: String },

    #[error("corrupt database: {0}")]
    Corrupt(&'static str),
}

/// A database handle: one connection, one role, one writer at a time.
pub struct Db {
    conn: Connection,
    role: Role,
    path: PathBuf,
}

impl fmt::Debug for Db {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Db")
            .field("path", &self.path)
            .field("role", &self.role)
            .finish()
    }
}

impl Db {
    /// Open (or create) a database for one end of the sync.
    ///
    /// Sets WAL, `synchronous=FULL`, foreign keys and a 5 s busy timeout, then
    /// migrates the schema and ensures the root object exists. The whole
    /// migration runs in one `BEGIN IMMEDIATE` transaction.
    pub fn open(path: impl AsRef<Path>, role: Role) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut conn = Connection::open(&path)?;
        // Readers reopen by path, so store an absolute, symlink-resolved path:
        // a later `chdir` in the daemon must not redirect them.
        let path = std::fs::canonicalize(&path).unwrap_or(path);
        configure(&conn, role)?;
        schema::migrate(&mut conn, role)?;
        Ok(Self { conn, role, path })
    }

    /// The role this database was created for.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The database file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The schema version recorded in `meta.schema_version`.
    pub fn schema_version(&self) -> Result<i64> {
        self.read()?.meta_i64(keys::SCHEMA_VERSION)
    }

    /// Open a read-only snapshot on its own connection.
    ///
    /// The connection is opened `READ_WRITE` (not `READ_ONLY`) so it can
    /// recover the WAL even if the writer closes first, then pinned with
    /// `query_only=ON` so no write can escape through it. A caller that wants
    /// many concurrent readers opens many `ReadTx` values; [`ReadPool`] caches
    /// the underlying connections for the client.
    pub fn read(&self) -> Result<ReadTx> {
        let conn = open_reader_connection(&self.path)?;
        begin_deferred(&conn)?;
        Ok(ReadTx {
            conn: Some(conn),
            role: self.role,
            pool: None,
        })
    }

    /// Open the single write transaction (`BEGIN IMMEDIATE`).
    pub fn write(&mut self) -> Result<WriteTx<'_>> {
        Ok(WriteTx {
            tx: self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?,
            role: self.role,
        })
    }

    /// Compute the state digest of the current tree.
    pub fn state_hash(&self) -> Result<[u8; 32]> {
        self.read()?.state_hash()
    }

    /// Fold the event log into a minimal replayable form.
    ///
    /// Server only. See [`WriteTx::compact`].
    pub fn compact(&mut self) -> Result<CompactReport> {
        let tx = self.write()?;
        let report = tx.compact()?;
        tx.commit()?;
        Ok(report)
    }

    /// Move the WAL back into the main database file and truncate it.
    ///
    /// The client runs this on unmount, after FUSE has stopped and before the
    /// connection is closed. It is an operational step, not a correctness one:
    /// SQLite recovers the WAL on the next open either way.
    pub fn checkpoint_wal(&self) -> Result<()> {
        self.checkpoint("TRUNCATE")
    }

    /// Copy as much of the WAL back into the main database as no reader is
    /// using, without waiting for readers or truncating the file.
    ///
    /// This is the background checkpoint: it never blocks the writer and
    /// never waits for a long read, so the WAL keeps growing while a snapshot
    /// is open and shrinks as soon as the snapshot ends.
    pub fn checkpoint_wal_passive(&self) -> Result<()> {
        self.checkpoint("PASSIVE")
    }

    fn checkpoint(&self, mode: &str) -> Result<()> {
        self.conn
            .query_row(&format!("PRAGMA wal_checkpoint({mode})"), [], |row| {
                row.get::<_, i64>(0)
            })?;
        Ok(())
    }
}

/// Open a read connection without running the schema migration.
///
/// The connection is `READ_WRITE` (not `READ_ONLY`) so it can recover the WAL
/// even if the writer closes first, and `query_only` so no write can escape
/// through it. Opening the database itself is the expensive part; callers that
/// read repeatedly should reuse the connection through [`ReadPool`].
fn open_reader_connection(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(Duration::from_millis(5_000))?;
    conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA query_only = ON;")?;
    Ok(conn)
}

fn begin_deferred(conn: &Connection) -> Result<()> {
    conn.execute_batch("BEGIN DEFERRED")?;
    Ok(())
}

fn configure(conn: &Connection, role: Role) -> Result<()> {
    conn.busy_timeout(Duration::from_millis(5_000))?;
    let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(StoreError::NotWal { mode });
    }
    // The server keeps FULL: a confirmed event must survive a power loss and
    // `seq` must never move backwards. A client is a rebuildable replica and
    // uses NORMAL; a lost recent local transaction is an accepted reconnect.
    // OFF is never used: it can corrupt the database, not merely lose a
    // watermark.
    let synchronous = if matches!(role, Role::Client) {
        "NORMAL"
    } else {
        "FULL"
    };
    conn.execute_batch(&format!(
        "PRAGMA synchronous = {synchronous}; PRAGMA foreign_keys = ON;"
    ))?;
    Ok(())
}

/// A read-only snapshot on its own connection.
///
/// A [`Db`] owns exactly one writer connection. Every [`Db::read`] call opens a
/// separate connection and starts a deferred transaction, so readers never
/// block the writer and never collide with each other. A [`ReadPool`] reader
/// returns its connection to the pool on drop instead of closing it; closing
/// or rolling back ends the transaction either way.
pub struct ReadTx {
    conn: Option<Connection>,
    role: Role,
    pool: Option<Arc<ReadPoolInner>>,
}

impl fmt::Debug for ReadTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadTx").field("role", &self.role).finish()
    }
}

impl Drop for ReadTx {
    fn drop(&mut self) {
        let Some(conn) = self.conn.take() else {
            return;
        };
        let Some(pool) = self.pool.take() else {
            // A standalone snapshot closes its connection, which ends the
            // transaction; no explicit rollback is needed.
            drop(conn);
            return;
        };
        // A snapshot that is dropped without a query is still an open
        // deferred transaction; end it before the connection can be reused.
        let clean = conn.execute_batch("ROLLBACK").is_ok();
        if clean {
            pool.recycle(conn);
        } else {
            pool.discard(conn);
        }
    }
}

impl ReadTx {
    /// The raw connection of this read snapshot.
    ///
    /// Escape hatch for role-table queries (`fuse_inos`, `outbox`, ...) that
    /// this module does not wrap yet. The connection is `query_only`, so a
    /// write through it fails. Core-table reads should use the typed methods.
    pub fn conn(&self) -> &Connection {
        match &self.conn {
            Some(conn) => conn,
            None => unreachable!("a read snapshot always owns its connection"),
        }
    }

    /// Read one meta value.
    pub fn get_meta(&self, key: &str) -> Result<Option<MetaValue>> {
        meta_get(self.conn(), key)
    }

    /// Read one integer meta value.
    pub fn meta_i64(&self, key: &str) -> Result<i64> {
        meta_i64(self.conn(), key)
    }

    /// Read one text meta value.
    pub fn meta_text(&self, key: &str) -> Result<String> {
        meta_text(self.conn(), key)
    }

    /// Read one blob meta value.
    pub fn meta_blob(&self, key: &str) -> Result<Vec<u8>> {
        meta_blob(self.conn(), key)
    }

    /// Read an object row.
    pub fn object(&self, ino: [u8; 16]) -> Result<Option<Object>> {
        object(self.conn(), ino)
    }

    /// Read an object by its canonical path.
    pub fn object_by_path(&self, path: &str) -> Result<Option<Object>> {
        object_by_path(self.conn(), path)
    }

    /// Read one directory entry.
    pub fn name(&self, parent: [u8; 16], name: &str) -> Result<Option<Name>> {
        name_row(self.conn(), parent, name)
    }

    /// List a directory's entries, ordered by name bytes.
    pub fn children(&self, parent: [u8; 16]) -> Result<Vec<Name>> {
        children(self.conn(), parent)
    }

    /// Read a file's ordered chunk list.
    pub fn object_chunks(&self, ino: [u8; 16]) -> Result<Vec<ChunkRef>> {
        object_chunks(self.conn(), ino)
    }

    /// Read one chunk row.
    pub fn chunk(&self, hash: [u8; 32]) -> Result<Option<Chunk>> {
        chunk(self.conn(), hash)
    }

    /// Read one event row.
    pub fn event(&self, seq: i64) -> Result<Option<EventRow>> {
        event(self.conn(), seq)
    }

    /// Read a page of events from one epoch.
    ///
    /// Returns rows with `epoch = epoch` and `seq > after_seq`, in ascending
    /// order, at most `limit` rows. `limit == 0` returns an empty page; a
    /// larger limit is clamped to [`MAX_EVENT_PAGE`]. A stale epoch is an
    /// error rather than an empty page, because an empty page looks like
    /// "caught up" to a caller.
    pub fn events_from(&self, epoch: i64, after_seq: i64, limit: u32) -> Result<Vec<EventRow>> {
        let current = meta_i64(self.conn(), keys::EPOCH)?;
        if epoch != current {
            return Err(StoreError::StaleEpoch {
                requested: epoch,
                current,
            });
        }
        events_from(self.conn(), epoch, after_seq, limit)
    }

    /// Number of rows in `events`.
    pub fn event_count(&self) -> Result<i64> {
        Ok(self
            .conn()
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?)
    }

    /// Read the server's `op_ids` row for an operation.
    pub fn op_id(&self, op_id: [u8; 16]) -> Result<Option<OpId>> {
        if self.role != Role::Server {
            return Err(StoreError::WrongRole {
                role: self.role,
                operation: "op_id",
            });
        }
        op_id_row(self.conn(), op_id)
    }

    /// Compute the state digest of the snapshot.
    pub fn state_hash(&self) -> Result<[u8; 32]> {
        hash::state_hash(self.conn())
    }
}

/// Read-pool limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadPoolConfig {
    /// Connections kept open at once, leased or idle.
    pub max_connections: usize,
    /// An idle connection older than this is closed on the next acquisition.
    pub idle_timeout: Duration,
    /// How long a reader waits for a slot before opening a temporary
    /// connection. A temporary connection is dropped on release, so a burst
    /// never leaves more than `max_connections` idle readers behind.
    pub acquire_timeout: Duration,
}

impl Default for ReadPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 8,
            idle_timeout: Duration::from_secs(60),
            acquire_timeout: Duration::from_secs(1),
        }
    }
}

/// Read-pool counters, for diagnostics and tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadPoolStats {
    /// Connections currently open, leased or idle.
    pub live: usize,
    /// Connections parked for reuse.
    pub idle: usize,
    /// Connections opened since the pool was created.
    pub opens: u64,
    /// Acquisitions that had to wait for a slot.
    pub waits: u64,
}

/// A bounded pool of long-lived read connections.
///
/// A FUSE thread leases a connection, runs one `BEGIN DEFERRED` snapshot and
/// returns the connection when [`ReadTx`] drops. Opening a SQLite connection
/// (and recovering the WAL) is the expensive part; this pool pays it once per
/// connection instead of once per read.
pub struct ReadPool {
    inner: Arc<ReadPoolInner>,
}

impl fmt::Debug for ReadPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadPool")
            .field("stats", &self.stats())
            .finish()
    }
}

impl ReadPool {
    /// Create a pool with the default limits.
    pub fn new(path: impl AsRef<Path>, role: Role) -> Self {
        Self::with_config(path, role, ReadPoolConfig::default())
    }

    /// Create a pool with explicit limits.
    pub fn with_config(path: impl AsRef<Path>, role: Role, config: ReadPoolConfig) -> Self {
        Self {
            inner: Arc::new(ReadPoolInner {
                path: path.as_ref().to_path_buf(),
                role,
                config,
                state: Mutex::new(PoolState::default()),
                available: Condvar::new(),
                opens: AtomicU64::new(0),
                waits: AtomicU64::new(0),
            }),
        }
    }

    /// Lease a connection and open a deferred snapshot on it.
    pub fn read(&self) -> Result<ReadTx> {
        let conn = self.acquire()?;
        if let Err(error) = begin_deferred(&conn) {
            // Never return a connection whose transaction state is unknown.
            self.inner.discard(conn);
            return Err(error);
        }
        Ok(ReadTx {
            conn: Some(conn),
            role: self.inner.role,
            pool: Some(Arc::clone(&self.inner)),
        })
    }

    /// Close connections that have been idle longer than `idle_timeout`.
    pub fn reap_idle(&self) {
        let mut state = self.inner.lock();
        let removed = self.inner.reap_locked(&mut state);
        drop(state);
        if removed > 0 {
            self.inner.available.notify_all();
        }
    }

    /// A snapshot of the pool counters.
    pub fn stats(&self) -> ReadPoolStats {
        let state = self.inner.lock();
        ReadPoolStats {
            live: state.live,
            idle: state.idle.len(),
            opens: self.inner.opens.load(Ordering::Relaxed),
            waits: self.inner.waits.load(Ordering::Relaxed),
        }
    }

    fn acquire(&self) -> Result<Connection> {
        let mut state = self.inner.lock();
        loop {
            let removed = self.inner.reap_locked(&mut state);
            if removed > 0 {
                self.inner.available.notify_all();
            }
            if let Some(reader) = state.idle.pop() {
                return Ok(reader.conn);
            }
            if state.live < self.inner.config.max_connections {
                state.live += 1;
                drop(state);
                return self.inner.open();
            }
            self.inner.waits.fetch_add(1, Ordering::Relaxed);
            let (next, timeout) = self
                .inner
                .available
                .wait_timeout(state, self.inner.config.acquire_timeout)
                .unwrap_or_else(PoisonError::into_inner);
            state = next;
            if timeout.timed_out() {
                // Every pooled slot stayed busy. Open one temporary
                // connection instead of stalling a FUSE callback; the lease
                // is accounted for and the connection is dropped on release.
                state.live += 1;
                drop(state);
                return self.inner.open();
            }
        }
    }
}

impl Drop for ReadPool {
    fn drop(&mut self) {
        self.inner.close();
    }
}

struct ReadPoolInner {
    path: PathBuf,
    role: Role,
    config: ReadPoolConfig,
    state: Mutex<PoolState>,
    available: Condvar,
    opens: AtomicU64,
    waits: AtomicU64,
}

impl ReadPoolInner {
    fn lock(&self) -> std::sync::MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn open(&self) -> Result<Connection> {
        match open_reader_connection(&self.path) {
            Ok(conn) => {
                self.opens.fetch_add(1, Ordering::Relaxed);
                Ok(conn)
            }
            Err(error) => {
                let mut state = self.lock();
                state.live = state.live.saturating_sub(1);
                drop(state);
                self.available.notify_one();
                Err(error)
            }
        }
    }

    /// Drop idle readers past `idle_timeout`; returns how many closed.
    fn reap_locked(&self, state: &mut PoolState) -> usize {
        let timeout = self.config.idle_timeout;
        let before = state.idle.len();
        state.idle.retain(|reader| reader.last_used.elapsed() < timeout);
        let removed = before - state.idle.len();
        state.live = state.live.saturating_sub(removed);
        removed
    }

    fn recycle(&self, conn: Connection) {
        let mut state = self.lock();
        if state.closed
            || state.live > self.config.max_connections
            || state.idle.len() >= self.config.max_connections
        {
            state.live = state.live.saturating_sub(1);
            drop(state);
            drop(conn);
        } else {
            state.idle.push(IdleReader {
                conn,
                last_used: Instant::now(),
            });
            drop(state);
        }
        self.available.notify_one();
    }

    fn discard(&self, conn: Connection) {
        let mut state = self.lock();
        state.live = state.live.saturating_sub(1);
        drop(state);
        drop(conn);
        self.available.notify_one();
    }

    fn close(&self) {
        let mut state = self.lock();
        state.closed = true;
        state.live = state.live.saturating_sub(state.idle.len());
        state.idle.clear();
        drop(state);
        self.available.notify_all();
    }
}

#[derive(Default)]
struct PoolState {
    idle: Vec<IdleReader>,
    live: usize,
    closed: bool,
}

struct IdleReader {
    conn: Connection,
    last_used: Instant,
}

/// The single write transaction. Dropping it without [`WriteTx::commit`] rolls
/// every change back.
pub struct WriteTx<'a> {
    tx: Transaction<'a>,
    role: Role,
}

impl fmt::Debug for WriteTx<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteTx").field("role", &self.role).finish()
    }
}

impl WriteTx<'_> {
    /// The raw connection of this write transaction.
    ///
    /// Escape hatch for role-table SQL (`outbox`, `outbox_chunks`, `locks`,
    /// `fuse_inos`) that this module does not wrap yet. It stays inside the
    /// same `BEGIN IMMEDIATE`, so it shares the transaction and its rollback.
    /// Core-table writes should still go through the typed methods: they
    /// validate rows and maintain chunk refcounts.
    pub fn conn(&self) -> &Connection {
        &self.tx
    }

    /// The role of the database this transaction belongs to.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Commit. Consuming `self` is deliberate: there is no way to commit twice.
    pub fn commit(self) -> Result<()> {
        self.tx.commit()?;
        Ok(())
    }

    /// Read one meta value inside the transaction.
    pub fn get_meta(&self, key: &str) -> Result<Option<MetaValue>> {
        meta_get(&self.tx, key)
    }

    /// Read one integer meta value inside the transaction.
    pub fn meta_i64(&self, key: &str) -> Result<i64> {
        meta_i64(&self.tx, key)
    }

    /// Read an object row inside the transaction.
    pub fn object(&self, ino: [u8; 16]) -> Result<Option<Object>> {
        object(&self.tx, ino)
    }

    /// Read an object by its canonical path inside the transaction.
    pub fn object_by_path(&self, path: &str) -> Result<Option<Object>> {
        object_by_path(&self.tx, path)
    }

    /// Read one directory entry inside the transaction.
    pub fn name(&self, parent: [u8; 16], name: &str) -> Result<Option<Name>> {
        name_row(&self.tx, parent, name)
    }

    /// List a directory's entries inside the transaction.
    pub fn children(&self, parent: [u8; 16]) -> Result<Vec<Name>> {
        children(&self.tx, parent)
    }

    /// Read a file's ordered chunk list inside the transaction.
    pub fn object_chunks(&self, ino: [u8; 16]) -> Result<Vec<ChunkRef>> {
        object_chunks(&self.tx, ino)
    }

    /// Read one chunk row inside the transaction.
    pub fn chunk(&self, hash: [u8; 32]) -> Result<Option<Chunk>> {
        chunk(&self.tx, hash)
    }

    /// Write one meta value.
    pub fn set_meta(&self, key: &str, value: MetaValue) -> Result<()> {
        meta_set(&self.tx, key, value)
    }

    /// Write one integer meta value.
    pub fn set_meta_i64(&self, key: &str, value: i64) -> Result<()> {
        meta_set(&self.tx, key, MetaValue::Integer(value))
    }

    /// Write one text meta value.
    pub fn set_meta_text(&self, key: &str, value: impl Into<String>) -> Result<()> {
        meta_set(&self.tx, key, MetaValue::Text(value.into()))
    }

    /// Write one blob meta value.
    pub fn set_meta_blob(&self, key: &str, value: &[u8]) -> Result<()> {
        meta_set(&self.tx, key, MetaValue::Blob(value.to_vec()))
    }

    /// Insert or update an object row.
    ///
    /// `created_seq` is preserved on update; every other column is replaced.
    pub fn put_object(&self, object: &Object) -> Result<()> {
        if object.mtime_ns < 0 {
            return Err(StoreError::OutOfRange {
                field: "mtime_ns",
                value: object.mtime_ns,
            });
        }
        let size = i64::try_from(object.size).map_err(|_| StoreError::OutOfRange {
            field: "size",
            value: i64::MAX,
        })?;
        match (object.kind, object.target.is_some()) {
            (ObjectKind::Symlink, false) => {
                return Err(StoreError::Corrupt("symlink without target"));
            }
            (ObjectKind::Symlink, true) => {}
            (_, true) => return Err(StoreError::Corrupt("target on a non-symlink")),
            (_, false) => {}
        }
        if object.deleted && object.nlink != 0 {
            return Err(StoreError::Corrupt("deleted object still has links"));
        }
        let deleted = if object.deleted { 1i64 } else { 0i64 };
        self.tx.execute(
            "INSERT INTO objects
               (ino, kind, mode, uid, gid, mtime_ns, size, file_root, block_count,
                target, nlink, deleted, created_seq, updated_seq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
             ON CONFLICT(ino) DO UPDATE SET
               kind = excluded.kind,
               mode = excluded.mode,
               uid = excluded.uid,
               gid = excluded.gid,
               mtime_ns = excluded.mtime_ns,
               size = excluded.size,
               file_root = excluded.file_root,
               block_count = excluded.block_count,
               target = excluded.target,
               nlink = excluded.nlink,
               deleted = excluded.deleted,
               updated_seq = excluded.updated_seq",
            params![
                object.ino.as_slice(),
                object.kind.as_str(),
                i64::from(object.mode),
                i64::from(object.uid),
                i64::from(object.gid),
                object.mtime_ns,
                size,
                object.file_root.as_slice(),
                i64::from(object.block_count),
                object.target,
                i64::from(object.nlink),
                deleted,
                object.created_seq,
                object.updated_seq,
            ],
        )?;
        Ok(())
    }

    /// Insert one directory entry.
    pub fn put_name(&self, parent: [u8; 16], name: &str, ino: [u8; 16], path: &str) -> Result<()> {
        validate_name(name)?;
        validate_path(path)?;
        self.tx.execute(
            "INSERT INTO names (parent, name, ino, path) VALUES (?1, ?2, ?3, ?4)",
            params![parent.as_slice(), name, ino.as_slice(), path],
        )?;
        Ok(())
    }

    /// Delete one directory entry. Returns true if a row was removed.
    pub fn delete_name(&self, parent: [u8; 16], name: &str) -> Result<bool> {
        self.tx.execute(
            "DELETE FROM names WHERE parent = ?1 AND name = ?2",
            params![parent.as_slice(), name],
        )?;
        Ok(self.tx.changes() > 0)
    }

    /// Insert or fill a chunk row.
    ///
    /// When `data` is present the hash and length are verified. A server must
    /// always have the bytes; a client may store only the hash (lazy cache).
    pub fn put_chunk(&self, hash: [u8; 32], len: u32, data: Option<&[u8]>) -> Result<()> {
        if let Some(bytes) = data {
            if bytes.len() != len as usize {
                return Err(StoreError::ChunkLengthMismatch {
                    hash,
                    declared: len,
                    actual: bytes.len(),
                });
            }
            if chunk_hash(bytes) != hash {
                return Err(StoreError::ChunkHashMismatch);
            }
        } else if self.role == Role::Server {
            return Err(StoreError::ChunkDataRequired { hash });
        }

        if let Some(existing) = chunk(&self.tx, hash)? {
            if existing.len != len {
                return Err(StoreError::ChunkLengthMismatch {
                    hash,
                    declared: len,
                    actual: existing.len as usize,
                });
            }
        }

        self.tx.execute(
            "INSERT INTO chunks (hash, len, data, refcount) VALUES (?1, ?2, ?3, 0)
             ON CONFLICT(hash) DO UPDATE SET data = COALESCE(chunks.data, excluded.data)",
            params![hash.as_slice(), i64::from(len), data],
        )?;
        Ok(())
    }

    /// Replace a file's chunk list and refresh the affected refcounts.
    ///
    /// The caller owns `objects.size`, `objects.block_count` and
    /// `objects.file_root`; this method only maintains `object_chunks`.
    pub fn set_object_chunks(&self, ino: [u8; 16], chunks: &[ChunkRef]) -> Result<()> {
        for (index, chunk) in chunks.iter().enumerate() {
            let expected_no = u32::try_from(index).map_err(|_| StoreError::OutOfRange {
                field: "chunk_no",
                value: i64::MAX,
            })?;
            if chunk.chunk_no != expected_no {
                return Err(StoreError::NonContiguousChunks { ino });
            }
            let expected_offset = u64::from(expected_no) * u64::from(CHUNK_BYTES);
            if chunk.offset != expected_offset {
                return Err(StoreError::ChunkOffsetMismatch {
                    chunk_no: chunk.chunk_no,
                    offset: chunk.offset,
                    expected: expected_offset,
                });
            }
            if chunk.len > CHUNK_BYTES {
                return Err(StoreError::OutOfRange {
                    field: "chunk len",
                    value: i64::from(chunk.len),
                });
            }
        }

        let old: Vec<[u8; 32]> = {
            let mut stmt = self
                .tx
                .prepare("SELECT chunk_hash FROM object_chunks WHERE ino = ?1")?;
            let mut rows = stmt.query([ino.as_slice()])?;
            let mut hashes = Vec::new();
            while let Some(row) = rows.next()? {
                hashes.push(read_blob32(row, 0)?);
            }
            hashes
        };

        self.tx
            .execute("DELETE FROM object_chunks WHERE ino = ?1", [ino.as_slice()])?;
        for chunk in chunks {
            let offset = i64::try_from(chunk.offset).map_err(|_| StoreError::OutOfRange {
                field: "chunk offset",
                value: i64::MAX,
            })?;
            self.tx.execute(
                "INSERT INTO object_chunks (ino, chunk_no, chunk_hash, offset, len)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    ino.as_slice(),
                    i64::from(chunk.chunk_no),
                    chunk.hash.as_slice(),
                    offset,
                    i64::from(chunk.len),
                ],
            )?;
        }

        let mut touched = old;
        touched.extend(chunks.iter().map(|chunk| chunk.hash));
        touched.sort_unstable();
        touched.dedup();
        self.refresh_refcounts(&touched)
    }

    /// Atomically increment and return `meta.seq`.
    ///
    /// Server only: the server is the sole assigner of event sequence numbers.
    /// The `UPDATE ... RETURNING` is one statement, so two writers cannot read
    /// the same value even without the surrounding transaction.
    pub fn bump_seq(&self) -> Result<i64> {
        if self.role != Role::Server {
            return Err(StoreError::WrongRole {
                role: self.role,
                operation: "bump_seq",
            });
        }
        let seq = self
            .tx
            .query_row(
                "UPDATE meta SET value = value + 1 WHERE key = ?1 RETURNING value",
                [keys::SEQ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        seq.ok_or_else(|| StoreError::MissingMeta(keys::SEQ.to_owned()))
    }

    /// Append one event.
    ///
    /// The caller supplies `seq`: on the server it comes from
    /// [`WriteTx::bump_seq`]; on a client it is the sequence number assigned by
    /// the server. Both `seq` and a non-NULL `op_id` are unique. A duplicate is
    /// reported as [`StoreError::DuplicateSeq`] or
    /// [`StoreError::DuplicateOp`] and inserts nothing; because `bump_seq` may
    /// already have advanced `meta.seq` in the same transaction, the caller
    /// must roll the transaction back to release that number.
    ///
    /// On the server, a `write` payload also fills `event_chunks` and updates
    /// the chunk refcounts.
    pub fn insert_event(&self, seq: i64, draft: EventDraft) -> Result<InsertedEvent> {
        self.append_event(seq, draft, true)
    }

    /// Record a server-side `op_id` after the event it produced was inserted.
    pub fn record_op_id(
        &self,
        op_id: [u8; 16],
        payload_hash: [u8; 32],
        first_seq: i64,
        seen_at: i64,
    ) -> Result<()> {
        if self.role != Role::Server {
            return Err(StoreError::WrongRole {
                role: self.role,
                operation: "record_op_id",
            });
        }
        if first_seq <= 0 {
            return Err(StoreError::OutOfRange {
                field: "first_seq",
                value: first_seq,
            });
        }
        if let Some(existing) = self
            .tx
            .query_row(
                "SELECT first_seq FROM op_ids WHERE op_id = ?1",
                [op_id.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
        {
            return Err(StoreError::DuplicateOp { op_id, existing });
        }
        self.tx.execute(
            "INSERT INTO op_ids (op_id, payload_hash, first_seq, seen_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                op_id.as_slice(),
                payload_hash.as_slice(),
                first_seq,
                seen_at
            ],
        )?;
        Ok(())
    }

    /// Compute the state digest inside the transaction.
    pub fn state_hash(&self) -> Result<[u8; 32]> {
        hash::state_hash(&self.tx)
    }

    /// Fold the event log into a minimal, replayable description of the
    /// current tree.
    ///
    /// Server only. The transaction performs:
    ///
    /// 1. clear `events`, `event_chunks` and `op_ids`;
    /// 2. advance `epoch`, reset `seq` to 0 and `replay_floor` to 1;
    /// 3. emit, for every live object: a `create_*` event (path-ordered, so
    ///    parents precede children), a `write` event carrying the current
    ///    chunk list for non-empty files, and a `setattr` event with the full
    ///    attributes;
    /// 4. emit a `link` event for every extra hard-link name;
    /// 5. refresh all chunk refcounts and rewrite `meta.state_hash`.
    ///
    /// The object, name and chunk tables are not modified, so the state digest
    /// is unchanged. Root is included as a `create_dir` at `/`; an applier
    /// must treat that as an update of the already-present root.
    ///
    /// Link counts are not carried in the payload. The applier convention is:
    /// `create_*` starts at 1 (2 for a directory, counting its own `.`
    /// entry), `link` increments, and creating a child directory increments
    /// the parent.
    ///
    /// `op_ids` is cleared, matching the design: a retry of an operation from
    /// before the compaction is no longer deduplicated by that table. The
    /// generated events carry deterministic `op_id`s derived from
    /// `(epoch, seq)`, so replaying the same log is idempotent.
    pub fn compact(&self) -> Result<CompactReport> {
        if self.role != Role::Server {
            return Err(StoreError::WrongRole {
                role: self.role,
                operation: "compact",
            });
        }

        let epoch = meta_i64(&self.tx, keys::EPOCH)? + 1;
        self.tx.execute("DELETE FROM event_chunks", [])?;
        self.tx.execute("DELETE FROM events", [])?;
        self.tx.execute("DELETE FROM op_ids", [])?;
        self.set_meta_i64(keys::EPOCH, epoch)?;
        self.set_meta_i64(keys::SEQ, 0)?;
        self.set_meta_i64(keys::REPLAY_FLOOR, 1)?;
        self.set_meta_i64(keys::COMPACTED_AT, now_secs())?;

        let live = collect_live_objects(&self.tx)?;
        let created_at = now_secs();
        let mut events = 0u64;
        let mut links = 0u64;

        for item in &live {
            let seq = self.bump_seq()?;
            let draft = EventDraft {
                epoch: Some(epoch),
                op_id: Some(compact_op_id(epoch, seq)),
                session_id: None,
                path: Some(item.path.clone()),
                path2: None,
                payload: create_payload(&item.object)?,
                result: "ok".to_owned(),
                created_at,
            };
            self.append_event(seq, draft, false)?;
            events += 1;
        }

        for item in &live {
            if item.object.kind.is_file() && !item.chunks.is_empty() {
                let seq = self.bump_seq()?;
                let draft = EventDraft {
                    epoch: Some(epoch),
                    op_id: Some(compact_op_id(epoch, seq)),
                    session_id: None,
                    path: Some(item.path.clone()),
                    path2: None,
                    payload: EventPayload::Write {
                        ino: item.object.ino,
                        offset: 0,
                        len: item.object.size,
                        size: item.object.size,
                        file_root: item.object.file_root,
                        mtime_ns: item.object.mtime_ns,
                        chunks: item.chunks.clone(),
                    },
                    result: "ok".to_owned(),
                    created_at,
                };
                self.append_event(seq, draft, false)?;
                events += 1;
            }
        }

        for item in &live {
            let seq = self.bump_seq()?;
            let draft = EventDraft {
                epoch: Some(epoch),
                op_id: Some(compact_op_id(epoch, seq)),
                session_id: None,
                path: Some(item.path.clone()),
                path2: None,
                payload: EventPayload::Setattr {
                    ino: item.object.ino,
                    mode: Some(item.object.mode),
                    uid: Some(item.object.uid),
                    gid: Some(item.object.gid),
                    mtime_ns: Some(item.object.mtime_ns),
                    size: None,
                },
                result: "ok".to_owned(),
                created_at,
            };
            self.append_event(seq, draft, false)?;
            events += 1;
        }

        for item in &live {
            for extra in &item.extra_paths {
                let seq = self.bump_seq()?;
                let draft = EventDraft {
                    epoch: Some(epoch),
                    op_id: Some(compact_op_id(epoch, seq)),
                    session_id: None,
                    // The live event convention is `path` = new name and
                    // `path2` = existing name; replay writes F_PATH from the
                    // former and F_TARGET from the latter.
                    path: Some(extra.clone()),
                    path2: Some(item.path.clone()),
                    payload: EventPayload::Link {
                        ino: item.object.ino,
                    },
                    result: "ok".to_owned(),
                    created_at,
                };
                self.append_event(seq, draft, false)?;
                events += 1;
                links += 1;
            }
        }

        self.refresh_all_refcounts()?;
        let state = hash::state_hash(&self.tx)?;
        self.set_meta_blob(keys::STATE_HASH, &state)?;

        Ok(CompactReport {
            epoch,
            objects: live.len() as u64,
            events,
            links,
        })
    }

    fn append_event(&self, seq: i64, draft: EventDraft, recount: bool) -> Result<InsertedEvent> {
        let kind = draft.validate()?;
        if seq <= 0 {
            return Err(StoreError::OutOfRange {
                field: "seq",
                value: seq,
            });
        }

        let current_epoch = meta_i64(&self.tx, keys::EPOCH)?;
        let epoch = match draft.epoch {
            Some(epoch) if epoch != current_epoch => {
                return Err(StoreError::StaleEpoch {
                    requested: epoch,
                    current: current_epoch,
                });
            }
            Some(epoch) => epoch,
            None => current_epoch,
        };

        if self
            .tx
            .query_row("SELECT 1 FROM events WHERE seq = ?1", [seq], |_| Ok(()))
            .optional()?
            .is_some()
        {
            return Err(StoreError::DuplicateSeq { seq });
        }
        if let Some(op_id) = draft.op_id {
            if let Some(existing) = self
                .tx
                .query_row(
                    "SELECT seq FROM events WHERE op_id = ?1",
                    [op_id.as_slice()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
            {
                return Err(StoreError::DuplicateOp { op_id, existing });
            }
        }

        let payload = draft.payload.encode()?;
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(StoreError::Codec(format!(
                "payload is {} bytes, limit is {MAX_PAYLOAD_BYTES}",
                payload.len()
            )));
        }
        let payload_hash = chunk_hash(&payload);
        let ino = draft.payload.ino();

        self.tx.execute(
            "INSERT INTO events
               (seq, epoch, op_id, session_id, kind, path, path2, ino, payload,
                result, applied, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, ?11)",
            params![
                seq,
                epoch,
                draft.op_id.as_ref().map(|value| value.as_slice()),
                draft.session_id.as_ref().map(|value| value.as_slice()),
                kind.as_str(),
                draft.path,
                draft.path2,
                ino.as_ref().map(|value| value.as_slice()),
                payload,
                draft.result,
                draft.created_at,
            ],
        )?;

        if self.role == Role::Server {
            let chunks = draft.payload.chunks();
            for chunk in chunks {
                let offset = i64::try_from(chunk.offset).map_err(|_| StoreError::OutOfRange {
                    field: "chunk offset",
                    value: i64::MAX,
                })?;
                self.tx.execute(
                    "INSERT INTO event_chunks (seq, chunk_no, chunk_hash, offset, len)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        seq,
                        i64::from(chunk.chunk_no),
                        chunk.hash.as_slice(),
                        offset,
                        i64::from(chunk.len),
                    ],
                )?;
            }
            if recount && !chunks.is_empty() {
                let hashes: Vec<[u8; 32]> = chunks.iter().map(|chunk| chunk.hash).collect();
                self.refresh_refcounts(&hashes)?;
            }
        }

        Ok(InsertedEvent { seq, payload_hash })
    }

    fn refresh_refcounts(&self, hashes: &[[u8; 32]]) -> Result<()> {
        if hashes.is_empty() {
            return Ok(());
        }
        let sql = match self.role {
            Role::Client => CLIENT_RECOUNT_ONE,
            Role::Server => SERVER_RECOUNT_ONE,
        };
        let mut stmt = self.tx.prepare(sql)?;
        for hash in hashes {
            stmt.execute([hash.as_slice()])?;
        }
        Ok(())
    }

    fn refresh_all_refcounts(&self) -> Result<()> {
        let sql = match self.role {
            Role::Client => CLIENT_RECOUNT_ALL,
            Role::Server => SERVER_RECOUNT_ALL,
        };
        self.tx.execute(sql, [])?;
        Ok(())
    }
}

/// Summary of one compaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompactReport {
    /// New epoch.
    pub epoch: i64,
    /// Live objects described by the new log.
    pub objects: u64,
    /// Events written in total.
    pub events: u64,
    /// Subset of `events` that are hard-link records.
    pub links: u64,
}

const CLIENT_RECOUNT_ONE: &str = r#"
UPDATE chunks SET refcount =
      (SELECT COUNT(*) FROM object_chunks oc WHERE oc.chunk_hash = chunks.hash)
    + (SELECT COUNT(*) FROM outbox_chunks x WHERE x.chunk_hash = chunks.hash)
WHERE hash = ?1
"#;

const CLIENT_RECOUNT_ALL: &str = r#"
UPDATE chunks SET refcount =
      (SELECT COUNT(*) FROM object_chunks oc WHERE oc.chunk_hash = chunks.hash)
    + (SELECT COUNT(*) FROM outbox_chunks x WHERE x.chunk_hash = chunks.hash)
"#;

const SERVER_RECOUNT_ONE: &str = r#"
UPDATE chunks SET refcount =
      (SELECT COUNT(*) FROM object_chunks oc WHERE oc.chunk_hash = chunks.hash)
    + (SELECT COUNT(*) FROM event_chunks x WHERE x.chunk_hash = chunks.hash)
WHERE hash = ?1
"#;

const SERVER_RECOUNT_ALL: &str = r#"
UPDATE chunks SET refcount =
      (SELECT COUNT(*) FROM object_chunks oc WHERE oc.chunk_hash = chunks.hash)
    + (SELECT COUNT(*) FROM event_chunks x WHERE x.chunk_hash = chunks.hash)
"#;

const SELECT_OBJECT: &str = "SELECT ino, kind, mode, uid, gid, mtime_ns, size, \
    file_root, block_count, target, nlink, deleted, created_seq, updated_seq \
    FROM objects WHERE ino = ?1";

const SELECT_OBJECT_BY_PATH: &str = "SELECT o.ino, o.kind, o.mode, o.uid, o.gid, \
    o.mtime_ns, o.size, o.file_root, o.block_count, o.target, o.nlink, o.deleted, \
    o.created_seq, o.updated_seq FROM objects o JOIN names n ON n.ino = o.ino \
    WHERE n.path = ?1";

const SELECT_NAME: &str =
    "SELECT parent, name, ino, path FROM names WHERE parent = ?1 AND name = ?2";

const SELECT_CHILDREN: &str =
    "SELECT parent, name, ino, path FROM names WHERE parent = ?1 ORDER BY name";

const SELECT_OBJECT_CHUNKS: &str =
    "SELECT chunk_no, chunk_hash, offset, len FROM object_chunks WHERE ino = ?1 ORDER BY chunk_no";

const SELECT_CHUNK: &str = "SELECT hash, len, data, refcount FROM chunks WHERE hash = ?1";

const SELECT_EVENT: &str = "SELECT seq, epoch, op_id, session_id, kind, path, path2, \
    ino, payload, result, applied, created_at FROM events WHERE seq = ?1";

const SELECT_EVENTS_FROM: &str = "SELECT seq, epoch, op_id, session_id, kind, path, path2, \
    ino, payload, result, applied, created_at FROM events \
    WHERE epoch = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3";

const SELECT_OP_ID: &str =
    "SELECT op_id, payload_hash, first_seq, seen_at FROM op_ids WHERE op_id = ?1";

const SELECT_LIVE_OBJECTS: &str = r#"
SELECT ino, kind, mode, uid, gid, mtime_ns, size, file_root, block_count, target,
       nlink, deleted, created_seq, updated_seq, path
FROM (
    SELECT o.ino AS ino,
           o.kind AS kind,
           o.mode AS mode,
           o.uid AS uid,
           o.gid AS gid,
           o.mtime_ns AS mtime_ns,
           o.size AS size,
           o.file_root AS file_root,
           o.block_count AS block_count,
           o.target AS target,
           o.nlink AS nlink,
           o.deleted AS deleted,
           o.created_seq AS created_seq,
           o.updated_seq AS updated_seq,
           MIN(n.path) AS path
    FROM objects o
    JOIN names n ON n.ino = o.ino
    WHERE o.deleted = 0
    GROUP BY o.ino
    UNION ALL
    SELECT o.ino, o.kind, o.mode, o.uid, o.gid, o.mtime_ns, o.size, o.file_root,
           o.block_count, o.target, o.nlink, o.deleted, o.created_seq,
           o.updated_seq, '/'
    FROM objects o
    WHERE o.ino = ?1 AND o.deleted = 0
)
ORDER BY path
"#;

fn meta_get(conn: &Connection, key: &str) -> Result<Option<MetaValue>> {
    let raw = conn
        .query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
            row.get::<_, Value>(0)
        })
        .optional()?;
    raw.map(MetaValue::try_from).transpose()
}

fn meta_i64(conn: &Connection, key: &str) -> Result<i64> {
    match meta_get(conn, key)? {
        Some(MetaValue::Integer(value)) => Ok(value),
        Some(other) => Err(StoreError::MetaType {
            key: key.to_owned(),
            expected: "integer",
            actual: other.type_name(),
        }),
        None => Err(StoreError::MissingMeta(key.to_owned())),
    }
}

fn meta_text(conn: &Connection, key: &str) -> Result<String> {
    match meta_get(conn, key)? {
        Some(MetaValue::Text(value)) => Ok(value),
        Some(other) => Err(StoreError::MetaType {
            key: key.to_owned(),
            expected: "text",
            actual: other.type_name(),
        }),
        None => Err(StoreError::MissingMeta(key.to_owned())),
    }
}

fn meta_blob(conn: &Connection, key: &str) -> Result<Vec<u8>> {
    match meta_get(conn, key)? {
        Some(MetaValue::Blob(value)) => Ok(value),
        Some(other) => Err(StoreError::MetaType {
            key: key.to_owned(),
            expected: "blob",
            actual: other.type_name(),
        }),
        None => Err(StoreError::MissingMeta(key.to_owned())),
    }
}

fn meta_set(conn: &Connection, key: &str, value: MetaValue) -> Result<()> {
    let value: Value = value.into();
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

fn read_blob16(row: &rusqlite::Row<'_>, index: usize) -> Result<[u8; 16]> {
    let bytes: Vec<u8> = row.get(index)?;
    bytes
        .try_into()
        .map_err(|_| StoreError::Corrupt("expected a 16-byte blob"))
}

fn read_blob32(row: &rusqlite::Row<'_>, index: usize) -> Result<[u8; 32]> {
    let bytes: Vec<u8> = row.get(index)?;
    bytes
        .try_into()
        .map_err(|_| StoreError::Corrupt("expected a 32-byte blob"))
}

fn read_opt_blob16(row: &rusqlite::Row<'_>, index: usize) -> Result<Option<[u8; 16]>> {
    let bytes: Option<Vec<u8>> = row.get(index)?;
    bytes
        .map(|value| {
            value
                .try_into()
                .map_err(|_| StoreError::Corrupt("expected a 16-byte blob"))
        })
        .transpose()
}

fn read_u32(row: &rusqlite::Row<'_>, index: usize) -> Result<u32> {
    let value: i64 = row.get(index)?;
    u32::try_from(value).map_err(|_| StoreError::OutOfRange {
        field: "integer",
        value,
    })
}

fn read_u64(row: &rusqlite::Row<'_>, index: usize) -> Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| StoreError::OutOfRange {
        field: "integer",
        value,
    })
}

fn object_from_row(row: &rusqlite::Row<'_>) -> Result<Object> {
    let ino = read_blob16(row, 0)?;
    let kind_text: String = row.get(1)?;
    let kind = ObjectKind::parse(&kind_text).ok_or(StoreError::Corrupt("unknown object kind"))?;
    let mode = read_u32(row, 2)?;
    let uid = read_u32(row, 3)?;
    let gid = read_u32(row, 4)?;
    let mtime_ns: i64 = row.get(5)?;
    let size = read_u64(row, 6)?;
    let file_root = read_blob32(row, 7)?;
    let block_count = read_u32(row, 8)?;
    let target: Option<Vec<u8>> = row.get(9)?;
    let nlink = read_u32(row, 10)?;
    let deleted: i64 = row.get(11)?;
    let created_seq: i64 = row.get(12)?;
    let updated_seq: i64 = row.get(13)?;
    Ok(Object {
        ino,
        kind,
        mode,
        uid,
        gid,
        mtime_ns,
        size,
        file_root,
        block_count,
        target,
        nlink,
        deleted: deleted != 0,
        created_seq,
        updated_seq,
    })
}

fn object(conn: &Connection, ino: [u8; 16]) -> Result<Option<Object>> {
    let mut stmt = conn.prepare(SELECT_OBJECT)?;
    let mut rows = stmt.query([ino.as_slice()])?;
    match rows.next()? {
        Some(row) => Ok(Some(object_from_row(row)?)),
        None => Ok(None),
    }
}

fn object_by_path(conn: &Connection, path: &str) -> Result<Option<Object>> {
    let mut stmt = conn.prepare(SELECT_OBJECT_BY_PATH)?;
    let mut rows = stmt.query([path])?;
    match rows.next()? {
        Some(row) => Ok(Some(object_from_row(row)?)),
        None => Ok(None),
    }
}

fn name_from_row(row: &rusqlite::Row<'_>) -> Result<Name> {
    Ok(Name {
        parent: read_blob16(row, 0)?,
        name: row.get(1)?,
        ino: read_blob16(row, 2)?,
        path: row.get(3)?,
    })
}

fn name_row(conn: &Connection, parent: [u8; 16], name: &str) -> Result<Option<Name>> {
    let mut stmt = conn.prepare(SELECT_NAME)?;
    let mut rows = stmt.query(params![parent.as_slice(), name])?;
    match rows.next()? {
        Some(row) => Ok(Some(name_from_row(row)?)),
        None => Ok(None),
    }
}

fn children(conn: &Connection, parent: [u8; 16]) -> Result<Vec<Name>> {
    let mut stmt = conn.prepare(SELECT_CHILDREN)?;
    let mut rows = stmt.query([parent.as_slice()])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(name_from_row(row)?);
    }
    Ok(out)
}

fn object_chunks(conn: &Connection, ino: [u8; 16]) -> Result<Vec<ChunkRef>> {
    let mut stmt = conn.prepare(SELECT_OBJECT_CHUNKS)?;
    let mut rows = stmt.query([ino.as_slice()])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let chunk_no = read_u32(row, 0)?;
        let hash = read_blob32(row, 1)?;
        let offset = read_u64(row, 2)?;
        let len = read_u32(row, 3)?;
        out.push(ChunkRef {
            chunk_no,
            hash,
            offset,
            len,
        });
    }
    Ok(out)
}

fn chunk(conn: &Connection, hash: [u8; 32]) -> Result<Option<Chunk>> {
    let mut stmt = conn.prepare(SELECT_CHUNK)?;
    let mut rows = stmt.query([hash.as_slice()])?;
    match rows.next()? {
        Some(row) => Ok(Some(Chunk {
            hash: read_blob32(row, 0)?,
            len: read_u32(row, 1)?,
            data: row.get(2)?,
            refcount: read_u32(row, 3)?,
        })),
        None => Ok(None),
    }
}

fn event_from_row(row: &rusqlite::Row<'_>) -> Result<EventRow> {
    let kind_text: String = row.get(4)?;
    let kind = EventKind::parse(&kind_text).ok_or(StoreError::Corrupt("unknown event kind"))?;
    let applied: i64 = row.get(10)?;
    Ok(EventRow {
        seq: row.get(0)?,
        epoch: row.get(1)?,
        op_id: read_opt_blob16(row, 2)?,
        session_id: read_opt_blob16(row, 3)?,
        kind,
        path: row.get(5)?,
        path2: row.get(6)?,
        ino: read_opt_blob16(row, 7)?,
        payload: row.get(8)?,
        result: row.get(9)?,
        applied: applied != 0,
        created_at: row.get(11)?,
    })
}

fn event(conn: &Connection, seq: i64) -> Result<Option<EventRow>> {
    let mut stmt = conn.prepare(SELECT_EVENT)?;
    let mut rows = stmt.query([seq])?;
    match rows.next()? {
        Some(row) => Ok(Some(event_from_row(row)?)),
        None => Ok(None),
    }
}

fn events_from(conn: &Connection, epoch: i64, after_seq: i64, limit: u32) -> Result<Vec<EventRow>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let limit = limit.min(MAX_EVENT_PAGE);
    let mut stmt = conn.prepare(SELECT_EVENTS_FROM)?;
    let mut rows = stmt.query(params![epoch, after_seq, i64::from(limit)])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(event_from_row(row)?);
    }
    Ok(out)
}

fn op_id_row(conn: &Connection, op_id: [u8; 16]) -> Result<Option<OpId>> {
    let mut stmt = conn.prepare(SELECT_OP_ID)?;
    let mut rows = stmt.query([op_id.as_slice()])?;
    match rows.next()? {
        Some(row) => Ok(Some(OpId {
            op_id: read_blob16(row, 0)?,
            payload_hash: read_blob32(row, 1)?,
            first_seq: row.get(2)?,
            seen_at: row.get(3)?,
        })),
        None => Ok(None),
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(StoreError::InvalidName("empty"));
    }
    if name == "." || name == ".." {
        return Err(StoreError::InvalidName("'.' and '..' are not entries"));
    }
    if name.contains('/') {
        return Err(StoreError::InvalidName("contains '/'"));
    }
    if name.contains('\0') {
        return Err(StoreError::InvalidName("contains NUL"));
    }
    if name.chars().count() > 255 {
        return Err(StoreError::InvalidName("longer than 255 characters"));
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<()> {
    if !path.starts_with('/') {
        return Err(StoreError::InvalidPath("does not start with '/'"));
    }
    if path == "/" {
        return Err(StoreError::InvalidPath("the root has no name"));
    }
    if path.contains('\0') {
        return Err(StoreError::InvalidPath("contains NUL"));
    }
    if path.len() > 4096 {
        return Err(StoreError::InvalidPath("longer than 4096 bytes"));
    }
    Ok(())
}

struct LiveObject {
    path: String,
    object: Object,
    chunks: Vec<ChunkRef>,
    extra_paths: Vec<String>,
}

fn collect_live_objects(conn: &Connection) -> Result<Vec<LiveObject>> {
    hash::ensure_live_root(conn)?;

    let mut out = Vec::new();
    {
        let mut stmt = conn.prepare(SELECT_LIVE_OBJECTS)?;
        let mut rows = stmt.query([ROOT_INO.as_slice()])?;
        while let Some(row) = rows.next()? {
            let object = object_from_row(row)?;
            let path: String = row.get(14)?;
            out.push(LiveObject {
                path,
                object,
                chunks: Vec::new(),
                extra_paths: Vec::new(),
            });
        }
    }

    let live: i64 = conn.query_row(
        "SELECT COUNT(*) FROM objects WHERE deleted = 0",
        [],
        |row| row.get(0),
    )?;
    let live = usize::try_from(live).map_err(|_| StoreError::Corrupt("negative object count"))?;
    if live != out.len() {
        return Err(StoreError::Corrupt("live object without a name"));
    }

    for item in &mut out {
        item.chunks = object_chunks(conn, item.object.ino)?;
        if item.object.kind.is_file() {
            if item.object.block_count as usize != item.chunks.len() {
                return Err(StoreError::Corrupt(
                    "file block_count does not match object_chunks",
                ));
            }
            let expected = item
                .chunks
                .last()
                .map_or(0, |chunk| chunk.offset + u64::from(chunk.len));
            if item.object.size != expected {
                return Err(StoreError::Corrupt(
                    "file size does not match object_chunks",
                ));
            }
        } else if !item.chunks.is_empty() {
            return Err(StoreError::Corrupt("non-file object has object_chunks"));
        }
        let mut stmt = conn.prepare("SELECT path FROM names WHERE ino = ?1 ORDER BY path")?;
        let mut rows = stmt.query([item.object.ino.as_slice()])?;
        while let Some(row) = rows.next()? {
            let path: String = row.get(0)?;
            if path != item.path {
                item.extra_paths.push(path);
            }
        }
    }

    Ok(out)
}

fn create_payload(object: &Object) -> Result<EventPayload> {
    Ok(match object.kind {
        ObjectKind::File => EventPayload::CreateFile {
            ino: object.ino,
            mode: object.mode,
            uid: object.uid,
            gid: object.gid,
            mtime_ns: object.mtime_ns,
            // The content is described by the following `write` event.
            file_root: file_root(ObjectKind::File, None, &[]),
        },
        ObjectKind::Dir => EventPayload::CreateDir {
            ino: object.ino,
            mode: object.mode,
            uid: object.uid,
            gid: object.gid,
            mtime_ns: object.mtime_ns,
            file_root: object.file_root,
        },
        ObjectKind::Symlink => {
            let target = object
                .target
                .clone()
                .ok_or(StoreError::Corrupt("symlink without target"))?;
            EventPayload::Symlink {
                ino: object.ino,
                mode: object.mode,
                uid: object.uid,
                gid: object.gid,
                mtime_ns: object.mtime_ns,
                target,
                file_root: object.file_root,
            }
        }
        other => return Err(StoreError::UnsupportedObject { kind: other }),
    })
}

fn compact_op_id(epoch: i64, seq: i64) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sm/v1/compact-op\0");
    hasher.update(&epoch.to_le_bytes());
    hasher.update(&seq.to_le_bytes());
    let digest = hasher.finalize();
    let mut op_id = [0u8; 16];
    op_id.copy_from_slice(&digest.as_bytes()[..16]);
    op_id
}

pub(crate) fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
        })
}
