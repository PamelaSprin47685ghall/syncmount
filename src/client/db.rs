//! The client's only persistent state: one SQLite database.
//!
//! The mountpoint is a view over this database; it holds no file tree of its
//! own. Every FUSE callback either reads a snapshot ([`ClientDb::read`]) or
//! runs one `BEGIN IMMEDIATE` transaction ([`ClientDb::write`]) that updates
//! `objects`/`names`/`chunks`/`object_chunks` and appends the matching row to
//! the durable `outbox` in the same commit.
//!
//! # Handles
//!
//! One `Mutex<Db>` owns the single writer. Reads lease a long-lived connection
//! from an eight-connection [`ReadPool`], so a FUSE callback pays one
//! `BEGIN DEFERRED` instead of opening SQLite. A third connection serves the
//! background PASSIVE checkpoint, and `fsync` only syncs the WAL; copying WAL
//! pages into the main database never sits on the `fsync` path.
//!
//! # Sequence and identity
//!
//! * `meta.local_seq` is a monotonic counter. It is the outbox order and is
//!   stored in `outbox.created_at` (the schema has no separate column).
//! * `op_id` is a random 128-bit value; for a create it is also the inode id,
//!   so both ends derive the same identity without a wire field.
//! * `meta.client_id` is a random 16-byte label that satisfies the protocol's
//!   `F_CLIENT_ID`; it is not an identity and PSK membership does not depend
//!   on it.
//! * `fuse_inos` maps the 128-bit id to the kernel's 64-bit `st_ino`.

use std::ffi::OsStr;
use std::future::Future;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::{OptionalExtension, params};
use rustix::fs::{FlockOperation, Mode, OFlags};

use crate::client::writeback::{WriteBuffer, WritebackConfig, WritebackStats};
use crate::store::Errno;
use crate::store::sqlite::{
    self, CHUNK_BYTES, ChunkRef, Db, EventKind, EventPayload, MetaValue, Object, ObjectKind,
    ROOT_INO, ReadPool, ReadPoolStats, ReadTx, Role, StoreError, WriteTx, keys,
};

/// Local inode identity. The same 16 bytes are the `objects.ino` key and the
/// left half of a `file_handle`.
pub type Ino = [u8; 16];

/// Bytes in one content chunk, as a `u64` for offset arithmetic.
pub(crate) const CHUNK: u64 = CHUNK_BYTES as u64;

/// `meta.local_seq`: the durable outbox order.
const KEY_LOCAL_SEQ: &str = "local_seq";

/// `meta.client_id`: the protocol's self-declared label.
const KEY_CLIENT_ID: &str = "client_id";

/// `meta.cluster_id`: the PSK-derived namespace guard.
const KEY_CLUSTER_ID: &str = "cluster_id";

/// `meta.needs_resync`: a rejection needs the server's authoritative tree.
pub(crate) const KEY_NEEDS_RESYNC: &str = "needs_resync";

/// `meta.replay_local`: after a replica reset, re-apply the pending outbox
/// locally once the server replay is caught up.
pub(crate) const KEY_REPLAY_LOCAL: &str = "replay_local";

/// One pending operation, as the uplink sees it.
#[derive(Clone, Debug)]
pub struct OutboxOp {
    pub op_id: [u8; 16],
    pub seq: i64,
    pub kind: EventKind,
    pub path: Option<String>,
    pub path2: Option<String>,
    pub ino: Option<Ino>,
    /// Encoded [`EventPayload`] (`version byte || bincode`).
    pub payload: Vec<u8>,
    /// Decoded payload, for wire fields and data reads.
    pub decoded: EventPayload,
    pub state: OutboxState,
}

/// Durable outbox state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboxState {
    Pending,
    Sent,
    Acked,
    Failed,
}

impl OutboxState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sent => "sent",
            Self::Acked => "acked",
            Self::Failed => "failed",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "pending" => Self::Pending,
            "sent" => Self::Sent,
            "acked" => Self::Acked,
            "failed" => Self::Failed,
            _ => return None,
        })
    }
}

/// A chunk plus its bytes, ready to travel on the wire.
#[derive(Clone, Debug)]
pub struct OutboxChunk {
    pub chunk_no: u32,
    pub hash: [u8; 32],
    pub offset: u64,
    pub len: u32,
    pub data: Option<Vec<u8>>,
}

/// What happened to an applied event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The event advanced `applied_seq`.
    Applied,
    /// The event was at or below the local watermark; nothing changed.
    Duplicate,
    /// The server rejected the operation; the outbox row is `failed`.
    Rejected,
}

/// Background WAL-checkpoint policy.
///
/// `fsync` no longer checkpoints: it only syncs the WAL. A PASSIVE
/// checkpoint runs on its own connection every `interval`, or earlier when
/// the WAL grows past `wal_bytes`. PASSIVE never waits for a reader, so a
/// long read delays the WAL reset but never the checkpoint call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointConfig {
    /// Longest time the WAL may go without a checkpoint.
    pub interval: Duration,
    /// WAL size that forces a checkpoint between intervals.
    pub wal_bytes: u64,
}

impl Default for CheckpointConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
            wal_bytes: 64 * 1024 * 1024,
        }
    }
}

impl CheckpointConfig {
    /// Read the policy from the environment.
    ///
    /// `SYNCMOUNT_CHECKPOINT_INTERVAL_MS` and
    /// `SYNCMOUNT_CHECKPOINT_WAL_MIB` override the defaults; an unreadable or
    /// zero value keeps the default.
    pub fn from_env() -> Self {
        let mut config = Self::default();
        if let Some(ms) = env_u64("SYNCMOUNT_CHECKPOINT_INTERVAL_MS") {
            config.interval = Duration::from_millis(ms.max(1));
        }
        if let Some(mib) = env_u64("SYNCMOUNT_CHECKPOINT_WAL_MIB") {
            config.wal_bytes = mib.saturating_mul(1024 * 1024);
        }
        config
    }
}

fn env_u64(key: &str) -> Option<u64> {
    std::env::var(key).ok()?.parse().ok()
}

/// The background checkpoint thread and its stop flag.
struct CheckpointThread {
    stop: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl CheckpointThread {
    fn new() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            thread: Mutex::new(None),
        }
    }
}

/// The client database and its single-instance lock.
pub struct ClientDb {
    write: Mutex<Db>,
    /// Long-lived read connections leased by FUSE callbacks.
    readers: ReadPool,
    /// One connection reserved for PASSIVE checkpoints and the shutdown
    /// TRUNCATE. It never serves a read, so a checkpoint never contends with
    /// the writer mutex.
    maintenance: Mutex<Db>,
    checkpoint: CheckpointThread,
    checkpoint_config: CheckpointConfig,
    /// Userspace write-back buffer. Reads consult it before SQLite; commits
    /// drain it into one transaction per inode.
    pub(crate) writeback: WriteBuffer,
    /// Wakes the uplink after a commit may have appended outbox rows.
    ///
    /// A permit survives until the uplink waits, so a write that lands while
    /// the uplink is busy is never lost.
    outbox_wake: tokio::sync::Notify,
    /// Outbox pages the uplink fetched. An idle session costs one scan per
    /// wakeup, so this counter is the observable cost of the idle path.
    outbox_scans: AtomicU64,
    /// `flock(LOCK_EX | LOCK_NB)` on the database file, held for the process
    /// lifetime. Dropping the descriptor releases it.
    _lock: OwnedFd,
    path: PathBuf,
    cluster: [u8; 16],
}

impl std::fmt::Debug for ClientDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientDb")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl ClientDb {
    /// Open (or create) the client database and take the single-instance lock.
    ///
    /// The database is created with `Db::open(..., Role::Client)`, which runs
    /// the WAL setup, schema migration and root insert. A second process on
    /// the same file fails with [`DbError::Locked`].
    pub fn open(path: impl AsRef<Path>, cluster: [u8; 16]) -> Result<Self, DbError> {
        Self::open_with_configs(
            path,
            cluster,
            WritebackConfig::default(),
            CheckpointConfig::from_env(),
        )
    }

    /// Open with an explicit write-back configuration.
    #[cfg(test)]
    pub(crate) fn open_with_writeback(
        path: impl AsRef<Path>,
        cluster: [u8; 16],
        writeback: WritebackConfig,
    ) -> Result<Self, DbError> {
        Self::open_with_configs(path, cluster, writeback, CheckpointConfig::default())
    }

    /// Open with explicit write-back and checkpoint configurations.
    pub(crate) fn open_with_configs(
        path: impl AsRef<Path>,
        cluster: [u8; 16],
        writeback: WritebackConfig,
        checkpoint: CheckpointConfig,
    ) -> Result<Self, DbError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(DbError::Io)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
        let lock = rustix::fs::open(
            &path,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::CREATE,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|err| DbError::Io(std::io::Error::from(err)))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(DbError::Io)?;
        }
        rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(
            |err| match err {
                rustix::io::Errno::WOULDBLOCK => DbError::Locked(path.clone()),
                other => DbError::Io(std::io::Error::from(other)),
            },
        )?;

        let write = Db::open(&path, Role::Client)?;
        // `Db::open` canonicalises the path; readers must use the same
        // absolute path so a later `chdir` cannot redirect them.
        let path = write.path().to_path_buf();
        let maintenance = Db::open(&path, Role::Client)?;
        let readers = ReadPool::new(&path, Role::Client);
        let store = Self {
            write: Mutex::new(write),
            readers,
            maintenance: Mutex::new(maintenance),
            checkpoint: CheckpointThread::new(),
            checkpoint_config: checkpoint,
            writeback: WriteBuffer::new(writeback),
            outbox_wake: tokio::sync::Notify::new(),
            outbox_scans: AtomicU64::new(0),
            _lock: lock,
            path,
            cluster,
        };
        store.initialize()?;
        Ok(store)
    }

    /// The database file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The PSK-derived cluster id this database belongs to.
    pub const fn cluster(&self) -> &[u8; 16] {
        &self.cluster
    }

    fn initialize(&self) -> Result<(), DbError> {
        self.write(|tx| {
            let stored = tx.get_meta(KEY_CLUSTER_ID)?;
            match stored {
                None => tx.set_meta_blob(KEY_CLUSTER_ID, &self.cluster)?,
                Some(MetaValue::Blob(bytes)) if bytes.as_slice() == self.cluster => {}
                Some(_) => {
                    return Err(DbError::ClusterMismatch);
                }
            }
            if tx.get_meta(KEY_CLIENT_ID)?.is_none() {
                let id = loop {
                    let candidate = rand::random::<u128>().to_le_bytes();
                    if candidate != [0u8; 16] {
                        break candidate;
                    }
                };
                tx.set_meta_blob(KEY_CLIENT_ID, &id)?;
            }
            if tx.get_meta(KEY_LOCAL_SEQ)?.is_none() {
                tx.set_meta_i64(KEY_LOCAL_SEQ, 0)?;
            }
            // Root is kernel inode 1. Backfill any object that arrived through
            // a replay before this build allocated one.
            tx.conn().execute(
                "INSERT OR IGNORE INTO fuse_inos (ino, fuse_ino) VALUES (?1, 1)",
                [ROOT_INO.as_slice()],
            )?;
            let next: i64 = tx.meta_i64(keys::FUSE_INO_NEXT).unwrap_or(2).max(2);
            let mut missing = Vec::new();
            {
                let mut stmt = tx.conn().prepare(
                    "SELECT ino FROM objects o WHERE NOT EXISTS
                       (SELECT 1 FROM fuse_inos f WHERE f.ino = o.ino)",
                )?;
                let mut rows = stmt.query([])?;
                while let Some(row) = rows.next()? {
                    let bytes: Vec<u8> = row.get(0)?;
                    if let Ok(ino) = <[u8; 16]>::try_from(bytes) {
                        missing.push(ino);
                    }
                }
            }
            let mut cursor = next;
            for ino in missing {
                tx.conn().execute(
                    "INSERT OR IGNORE INTO fuse_inos (ino, fuse_ino) VALUES (?1, ?2)",
                    params![ino.as_slice(), cursor],
                )?;
                cursor += 1;
            }
            tx.set_meta_i64(keys::FUSE_INO_NEXT, cursor)?;
            Ok(())
        })
    }

    // -- write-back buffer -------------------------------------------------

    /// Start the periodic committer. The FUSE runtime calls this once the
    /// database is shared; tests may call it to observe the interval.
    pub fn start_writeback(self: &Arc<Self>) {
        self.writeback.start(self);
    }

    /// Stop and join the periodic committer.
    pub fn stop_writeback(&self) {
        self.writeback.stop();
    }

    /// Start the background PASSIVE checkpoint thread.
    ///
    /// The thread runs every [`CheckpointConfig::interval`], or earlier when
    /// the WAL file grows past [`CheckpointConfig::wal_bytes`]. It also
    /// reclaims idle read connections.
    pub fn start_checkpoint(self: &Arc<Self>) {
        let mut slot = self
            .checkpoint
            .thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if slot.is_some() {
            return;
        }
        self.checkpoint.stop.store(false, Ordering::Relaxed);
        let weak = Arc::downgrade(self);
        let stop = Arc::clone(&self.checkpoint.stop);
        let config = self.checkpoint_config;
        match std::thread::Builder::new()
            .name("syncmount-checkpoint".to_owned())
            .spawn(move || checkpoint_loop(weak, stop, config))
        {
            Ok(handle) => *slot = Some(handle),
            Err(error) => {
                tracing::warn!(
                    event = "checkpoint",
                    error = %error,
                    "cannot start the checkpoint thread"
                );
            }
        }
    }

    /// Stop and join the background checkpoint thread.
    pub fn stop_checkpoint(&self) {
        self.checkpoint.stop.store(true, Ordering::Relaxed);
        let handle = self
            .checkpoint
            .thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }

    /// Run one PASSIVE checkpoint now.
    pub(crate) fn checkpoint_passive(&self) -> Result<(), DbError> {
        let db = self
            .maintenance
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        db.checkpoint_wal_passive()?;
        Ok(())
    }

    /// Refresh `meta.state_hash` when a replay batch left it pending.
    ///
    /// The commit hook amortizes the tree walk over a batch budget; this
    /// drains the last few events on the background checkpoint thread.
    /// Returns true when a digest was written.
    pub(crate) fn refresh_state_hash_pending(&self) -> Result<bool, DbError> {
        // The common case is nothing to do; avoid taking the writer lock for
        // an empty transaction on every background tick.
        if self.read()?.meta_i64(keys::STATE_HASH_PENDING).unwrap_or(0) == 0 {
            return Ok(false);
        }
        let mut db = self.lock_writer();
        let tx = db.write()?;
        if tx.meta_i64(keys::STATE_HASH_PENDING).unwrap_or(0) == 0 {
            return Ok(false);
        }
        let applied = tx.meta_i64(keys::APPLIED_SEQ)?;
        let Ok(state) = tx.state_hash() else {
            // The tree is not consistent yet; the next batch or tick retries.
            return Ok(false);
        };
        tx.set_meta_blob(keys::STATE_HASH, &state)?;
        tx.set_meta_i64(keys::STATE_HASH_SEQ, applied)?;
        tx.set_meta_i64(keys::STATE_HASH_AT, sqlite::now_secs())?;
        tx.set_meta_i64(keys::STATE_HASH_PENDING, 0)?;
        tx.commit()?;
        Ok(true)
    }

    /// Move the WAL back into the main database and truncate it.
    ///
    /// Called at unmount, after FUSE and the session have stopped.
    #[cfg_attr(not(feature = "fuse"), allow(dead_code))]
    pub(crate) fn checkpoint_truncate(&self) -> Result<(), DbError> {
        let db = self
            .maintenance
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        db.checkpoint_wal()?;
        Ok(())
    }

    /// Size of the WAL file, or zero when there is none.
    pub fn wal_bytes(&self) -> u64 {
        std::fs::metadata(self.wal_path())
            .map(|metadata| metadata.len())
            .unwrap_or(0)
    }

    fn wal_path(&self) -> PathBuf {
        let mut path = self.path.as_os_str().to_owned();
        path.push("-wal");
        PathBuf::from(path)
    }

    /// Sync the WAL file to stable storage without a checkpoint.
    ///
    /// A commit in WAL mode writes frames to the WAL but `synchronous=NORMAL`
    /// does not fsync them. `fsync` only needs those frames on disk; the
    /// background PASSIVE checkpoint decides when to copy them back.
    pub(crate) fn sync_wal(&self) -> Result<(), DbError> {
        match std::fs::File::open(self.wal_path()) {
            Ok(file) => file.sync_all().map_err(DbError::Io),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(DbError::Io(error)),
        }
    }

    /// Read-pool counters, for status and tests.
    pub fn read_pool_stats(&self) -> ReadPoolStats {
        self.readers.stats()
    }

    /// Close read connections that have been idle past the pool timeout.
    pub fn reap_readers(&self) {
        self.readers.reap_idle();
    }

    /// Commit every buffered write.
    pub fn flush_all(&self) -> Result<(), DbError> {
        self.writeback.flush_all(self)
    }

    /// Commit one inode's buffered writes.
    pub fn flush_ino(&self, ino: Ino) -> Result<(), DbError> {
        self.writeback.flush_ino(self, ino)
    }

    /// Write-back counters, for logs and status.
    pub fn writeback_stats(&self) -> WritebackStats {
        self.writeback.stats()
    }

    /// Commit everything, for the background thread.
    pub(crate) fn commit_pending(&self) -> Result<(), DbError> {
        self.writeback.flush_pending(self)
    }

    /// Test access to the buffer.
    #[cfg(test)]
    pub(crate) fn writeback(&self) -> &WriteBuffer {
        &self.writeback
    }

    // -- transactions ------------------------------------------------------

    /// Lease a pooled read connection and open a consistent snapshot.
    ///
    /// No connection is opened: the pool keeps up to eight readers alive and
    /// hands one to this snapshot. Dropping the snapshot rolls the deferred
    /// transaction back and returns the connection to the pool.
    pub fn read(&self) -> Result<ReadTx, DbError> {
        Ok(self.readers.read()?)
    }

    /// Run one immediate write transaction and commit it.
    pub fn write<T>(
        &self,
        body: impl FnOnce(&WriteTx<'_>) -> Result<T, DbError>,
    ) -> Result<T, DbError> {
        let mut db = self.lock_writer();
        let tx = db.write()?;
        let value = body(&tx)?;
        tx.commit()?;
        self.wake_uplink();
        Ok(value)
    }

    /// Wake the uplink because a commit may have appended outbox rows.
    ///
    /// Called after the transaction has committed, never before: the uplink
    /// must not see a row that a rollback would remove.
    pub(crate) fn wake_uplink(&self) {
        self.outbox_wake.notify_one();
    }

    /// Resolve after [`ClientDb::wake_uplink`] has been called.
    ///
    /// One permit is retained while no waiter exists, so the uplink can call
    /// this after it drained the outbox and still observe an earlier write.
    pub(crate) fn uplink_notified(&self) -> impl Future<Output = ()> + '_ {
        self.outbox_wake.notified()
    }

    /// Record one outbox page scan by the uplink.
    pub(crate) fn note_outbox_scan(&self) {
        self.outbox_scans.fetch_add(1, Ordering::Relaxed);
    }

    /// Number of outbox page scans since the database opened.
    ///
    /// An idle event-driven uplink advances this a few times per second; a
    /// fixed 2 ms poll advances it about five thousand times per ten seconds.
    pub fn outbox_scans(&self) -> u64 {
        self.outbox_scans.load(Ordering::Relaxed)
    }

    pub(crate) fn lock_writer(&self) -> MutexGuard<'_, Db> {
        self.write.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The durable watermark: the last server sequence applied to the tree.
    pub fn applied_seq(&self) -> Result<i64, DbError> {
        let tx = self.read()?;
        Ok(tx.meta_i64(keys::APPLIED_SEQ)?)
    }

    /// The server epoch last seen.
    pub fn epoch(&self) -> Result<i64, DbError> {
        let tx = self.read()?;
        Ok(tx.meta_i64(keys::EPOCH)?)
    }

    /// True when a rejection needs the server's authoritative tree.
    pub fn needs_resync(&self) -> Result<bool, DbError> {
        let tx = self.read()?;
        Ok(tx.meta_i64(KEY_NEEDS_RESYNC).unwrap_or(0) != 0)
    }

    /// Record that the next handshake must rebuild the replica from the
    /// server log. The rejected local effect stays until that replay.
    pub fn mark_needs_resync(&self) -> Result<(), DbError> {
        self.write(|tx| {
            tx.set_meta_i64(KEY_NEEDS_RESYNC, 1)?;
            Ok(())
        })
    }

    /// Clear the resync request after the replica reset.
    pub fn clear_needs_resync(&self) -> Result<(), DbError> {
        self.write(|tx| {
            tx.set_meta_i64(KEY_NEEDS_RESYNC, 0)?;
            Ok(())
        })
    }

    /// Consume the "re-apply the pending outbox after replay" flag.
    pub fn take_replay_local(&self) -> Result<bool, DbError> {
        self.write(|tx| {
            let value = tx.meta_i64(KEY_REPLAY_LOCAL).unwrap_or(0);
            tx.set_meta_i64(KEY_REPLAY_LOCAL, 0)?;
            Ok(value != 0)
        })
    }

    /// The protocol's self-declared client label.
    pub fn client_id(&self) -> Result<[u8; 16], DbError> {
        let tx = self.read()?;
        match tx.get_meta(KEY_CLIENT_ID)? {
            Some(MetaValue::Blob(bytes)) => bytes
                .try_into()
                .map_err(|_| DbError::Corrupt("client_id is not 16 bytes")),
            _ => Err(DbError::Corrupt("client_id is missing")),
        }
    }

    /// Whether the local tree has anything beyond the root.
    pub fn has_content(&self) -> Result<bool, DbError> {
        let tx = self.read()?;
        let live: i64 = tx.conn().query_row(
            "SELECT COUNT(*) FROM objects WHERE deleted = 0 AND ino <> ?1",
            [ROOT_INO.as_slice()],
            |row| row.get(0),
        )?;
        Ok(live > 0)
    }

    /// Outbox occupancy for the status document.
    pub fn outbox_depth(&self) -> Result<(u64, u64), DbError> {
        let tx = self.read()?;
        let (ops, bytes): (i64, i64) = tx.conn().query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(payload)), 0) FROM outbox
             WHERE state IN ('pending', 'sent')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok((ops.max(0) as u64, bytes.max(0) as u64))
    }

    /// Number of rows in one outbox state.
    pub fn outbox_count(&self, state: OutboxState) -> Result<u64, DbError> {
        let tx = self.read()?;
        let count: i64 = tx.conn().query_row(
            "SELECT COUNT(*) FROM outbox WHERE state = ?1",
            [state.as_str()],
            |row| row.get(0),
        )?;
        Ok(count.max(0) as u64)
    }

    // -- kernel inode mapping ---------------------------------------------

    /// The kernel `st_ino` for one object.
    pub fn fuse_ino(&self, ino: Ino) -> Result<u64, DbError> {
        let tx = self.read()?;
        let value: Option<i64> = tx
            .conn()
            .query_row(
                "SELECT fuse_ino FROM fuse_inos WHERE ino = ?1",
                [ino.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        value
            .map(|value| value as u64)
            .ok_or(DbError::Errno(Errno::ENOENT))
    }

    /// The object behind one kernel inode.
    pub fn ino_by_fuse(&self, fuse_ino: u64) -> Result<Option<Ino>, DbError> {
        let tx = self.read()?;
        let bytes: Option<Vec<u8>> = tx
            .conn()
            .query_row(
                "SELECT ino FROM fuse_inos WHERE fuse_ino = ?1",
                [fuse_ino as i64],
                |row| row.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| {
                bytes
                    .try_into()
                    .map_err(|_| DbError::Corrupt("fuse_inos.ino is not 16 bytes"))
            })
            .transpose()
    }

    /// The parent directory of one entry, or the inode itself for the root.
    pub fn parent_of(&self, ino: Ino) -> Result<Ino, DbError> {
        if ino == ROOT_INO {
            return Ok(ROOT_INO);
        }
        let tx = self.read()?;
        let bytes: Option<Vec<u8>> = tx
            .conn()
            .query_row(
                "SELECT parent FROM names WHERE ino = ?1 ORDER BY path LIMIT 1",
                [ino.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        match bytes {
            Some(bytes) => bytes
                .try_into()
                .map_err(|_| DbError::Corrupt("names.parent is not 16 bytes")),
            None => Ok(ino),
        }
    }

    /// The canonical path of one object (the smallest `names.path`).
    pub fn path_of(&self, ino: Ino) -> Result<String, DbError> {
        let tx = self.read()?;
        if ino == ROOT_INO {
            return Ok("/".to_owned());
        }
        let path: Option<String> = tx
            .conn()
            .query_row(
                "SELECT path FROM names WHERE ino = ?1 ORDER BY path LIMIT 1",
                [ino.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        path.ok_or(DbError::Errno(Errno::ENOENT))
    }

    // -- read side ---------------------------------------------------------

    /// Resolve one directory entry.
    pub fn lookup(&self, parent: Ino, name: &OsStr) -> Result<Object, DbError> {
        // Hold the buffer read lock across the SQLite snapshot: a commit
        // either still shows its committing copy here or has already made the
        // bytes visible to the snapshot.
        let state = self.writeback.state_read();
        let mut object = self.lookup_durable(parent, name)?;
        state.overlay_object(object.ino, &mut object);
        Ok(object)
    }

    fn lookup_durable(&self, parent: Ino, name: &OsStr) -> Result<Object, DbError> {
        let name = name.to_str().ok_or(DbError::Errno(Errno::EINVAL))?;
        let tx = self.read()?;
        let entry = tx
            .name(parent, name)?
            .ok_or(DbError::Errno(Errno::ENOENT))?;
        let object = tx.object(entry.ino)?.ok_or(DbError::Errno(Errno::ENOENT))?;
        if object.deleted {
            return Err(DbError::Errno(Errno::ENOENT));
        }
        Ok(object)
    }

    /// Resolve an absolute path to its object.
    pub fn lookup_by_path(&self, path: &str) -> Result<Object, DbError> {
        let state = self.writeback.state_read();
        let mut object = self.lookup_by_path_durable(path)?;
        state.overlay_object(object.ino, &mut object);
        Ok(object)
    }

    fn lookup_by_path_durable(&self, path: &str) -> Result<Object, DbError> {
        let tx = self.read()?;
        let object = tx
            .object_by_path(path)?
            .ok_or(DbError::Errno(Errno::ENOENT))?;
        if object.deleted {
            return Err(DbError::Errno(Errno::ENOENT));
        }
        Ok(object)
    }

    /// Read one object.
    pub fn getattr(&self, ino: Ino) -> Result<Object, DbError> {
        let state = self.writeback.state_read();
        let mut object = self.getattr_durable(ino)?;
        state.overlay_object(ino, &mut object);
        Ok(object)
    }

    fn getattr_durable(&self, ino: Ino) -> Result<Object, DbError> {
        let tx = self.read()?;
        let object = tx.object(ino)?.ok_or(DbError::Errno(Errno::ENOENT))?;
        if object.deleted {
            return Err(DbError::Errno(Errno::ENOENT));
        }
        Ok(object)
    }

    /// List one directory in name order.
    pub fn children(&self, parent: Ino) -> Result<Vec<(String, Ino, ObjectKind)>, DbError> {
        let tx = self.read()?;
        let mut stmt = tx.conn().prepare(
            "SELECT n.name, n.ino, o.kind FROM names n
             JOIN objects o ON o.ino = n.ino
             WHERE n.parent = ?1 AND o.deleted = 0
             ORDER BY n.name",
        )?;
        let mut rows = stmt.query([parent.as_slice()])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let name: String = row.get(0)?;
            let bytes: Vec<u8> = row.get(1)?;
            let ino: Ino = bytes
                .try_into()
                .map_err(|_| DbError::Corrupt("names.ino is not 16 bytes"))?;
            let kind_text: String = row.get(2)?;
            let kind =
                ObjectKind::parse(&kind_text).ok_or(DbError::Corrupt("unknown object kind"))?;
            out.push((name, ino, kind));
        }
        Ok(out)
    }

    /// Read a byte range of a regular file.
    ///
    /// Holes are zero-filled. A chunk whose bytes are not cached yet is
    /// [`DbError::MissingChunk`], not silent zeroes.
    pub fn read_at(&self, ino: Ino, off: u64, len: u32) -> Result<Vec<u8>, DbError> {
        let state = self.writeback.state_read();
        let mut data = self.read_at_durable(ino, off, len)?;
        state.overlay_read(ino, off, len, &mut data);
        Ok(data)
    }

    fn read_at_durable(&self, ino: Ino, off: u64, len: u32) -> Result<Vec<u8>, DbError> {
        let tx = self.read()?;
        let object = tx.object(ino)?.ok_or(DbError::Errno(Errno::ENOENT))?;
        if object.deleted {
            return Err(DbError::Errno(Errno::ENOENT));
        }
        if object.kind.is_dir() {
            return Err(DbError::Errno(Errno::EISDIR));
        }
        if !object.kind.is_file() {
            return Err(DbError::Errno(Errno::EINVAL));
        }
        let start = off.min(object.size);
        let end = off.saturating_add(u64::from(len)).min(object.size);
        let mut out = vec![0u8; (end - start) as usize];
        if out.is_empty() {
            return Ok(out);
        }
        let refs = tx.object_chunks(ino)?;
        for chunk_ref in refs {
            let chunk_start = chunk_ref.offset;
            let chunk_end = chunk_start + u64::from(chunk_ref.len);
            let copy_start = start.max(chunk_start);
            let copy_end = end.min(chunk_end);
            if copy_start >= copy_end {
                continue;
            }
            let chunk = tx
                .chunk(chunk_ref.hash)?
                .ok_or(DbError::MissingChunk(chunk_ref.hash))?;
            let data = chunk.data.ok_or(DbError::MissingChunk(chunk_ref.hash))?;
            let from = (copy_start - chunk_start) as usize;
            let to = (copy_end - chunk_start) as usize;
            let at = (copy_start - start) as usize;
            out[at..at + (to - from)].copy_from_slice(&data[from..to]);
        }
        Ok(out)
    }

    /// Read a symbolic-link target.
    pub fn readlink(&self, ino: Ino) -> Result<Vec<u8>, DbError> {
        let object = self.getattr(ino)?;
        if object.kind != ObjectKind::Symlink {
            return Err(DbError::Errno(Errno::EINVAL));
        }
        object
            .target
            .ok_or(DbError::Corrupt("symlink without target"))
    }

    /// Directory-entry count for `statfs`-style reporting.
    pub fn object_count(&self) -> Result<u64, DbError> {
        let tx = self.read()?;
        let count: i64 = tx.conn().query_row(
            "SELECT COUNT(*) FROM objects WHERE deleted = 0",
            [],
            |row| row.get(0),
        )?;
        Ok(count.max(0) as u64)
    }

    // -- local mutation primitives ----------------------------------------

    /// Insert an outbox row and its chunk references inside `tx`.
    pub(crate) fn enqueue(
        tx: &WriteTx<'_>,
        op_id: [u8; 16],
        payload: &EventPayload,
        path: Option<&str>,
        path2: Option<&str>,
        chunks: &[ChunkRef],
        seq: i64,
    ) -> Result<(), DbError> {
        let encoded = payload.encode()?;
        tx.conn().execute(
            "INSERT INTO outbox
               (op_id, kind, path, path2, ino, payload, undo, state, attempts, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 'pending', 0, ?7)",
            params![
                op_id.as_slice(),
                payload.kind().as_str(),
                path,
                path2,
                payload.ino().map(|ino| ino.to_vec()),
                encoded,
                seq,
            ],
        )?;
        for chunk in chunks {
            tx.conn().execute(
                "INSERT INTO outbox_chunks (op_id, chunk_no, chunk_hash, offset, len)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    op_id.as_slice(),
                    i64::from(chunk.chunk_no),
                    chunk.hash.as_slice(),
                    i64::try_from(chunk.offset).unwrap_or(i64::MAX),
                    i64::from(chunk.len),
                ],
            )?;
        }
        tx.set_meta_i64(keys::DIRTY, 1)?;
        Ok(())
    }

    /// Allocate the next `local_seq`.
    pub(crate) fn next_local_seq(tx: &WriteTx<'_>) -> Result<i64, DbError> {
        let seq: Option<i64> = tx
            .conn()
            .query_row(
                "UPDATE meta SET value = value + 1 WHERE key = ?1 RETURNING value",
                [KEY_LOCAL_SEQ],
                |row| row.get(0),
            )
            .optional()?;
        seq.ok_or(DbError::Corrupt("local_seq is missing"))
    }

    /// Allocate the next kernel inode number.
    pub(crate) fn next_fuse_ino(tx: &WriteTx<'_>, ino: Ino) -> Result<u64, DbError> {
        if let Some(existing) = Self::fuse_ino_in(tx, ino)? {
            return Ok(existing);
        }
        let value: Option<i64> = tx
            .conn()
            .query_row(
                "UPDATE meta SET value = value + 1 WHERE key = ?1 RETURNING value - 1",
                [keys::FUSE_INO_NEXT],
                |row| row.get(0),
            )
            .optional()?;
        let fuse_ino = value.ok_or(DbError::Corrupt("fuse_ino_next is missing"))?;
        tx.conn().execute(
            "INSERT INTO fuse_inos (ino, fuse_ino) VALUES (?1, ?2)",
            params![ino.as_slice(), fuse_ino],
        )?;
        Ok(fuse_ino as u64)
    }

    pub(crate) fn fuse_ino_in(tx: &WriteTx<'_>, ino: Ino) -> Result<Option<u64>, DbError> {
        let value: Option<i64> = tx
            .conn()
            .query_row(
                "SELECT fuse_ino FROM fuse_inos WHERE ino = ?1",
                [ino.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value.map(|value| value as u64))
    }

    /// Resolve a path to an inode inside a write transaction.
    pub(crate) fn ino_by_path_in(tx: &WriteTx<'_>, path: &str) -> Result<Ino, DbError> {
        if path == "/" {
            return Ok(ROOT_INO);
        }
        let bytes: Option<Vec<u8>> = tx
            .conn()
            .query_row("SELECT ino FROM names WHERE path = ?1", [path], |row| {
                row.get(0)
            })
            .optional()?;
        bytes
            .map(|bytes| {
                bytes
                    .try_into()
                    .map_err(|_| DbError::Corrupt("names.ino is not 16 bytes"))
            })
            .transpose()?
            .ok_or(DbError::Errno(Errno::ENOENT))
    }

    /// Read an object inside a write transaction.
    pub(crate) fn object_in(tx: &WriteTx<'_>, ino: Ino) -> Result<Option<Object>, DbError> {
        let mut stmt = tx.conn().prepare(
            "SELECT ino, kind, mode, uid, gid, mtime_ns, size, file_root,
                    block_count, target, nlink, deleted, created_seq, updated_seq
             FROM objects WHERE ino = ?1",
        )?;
        let mut rows = stmt.query([ino.as_slice()])?;
        match rows.next()? {
            Some(row) => Ok(Some(object_from_row(row)?)),
            None => Ok(None),
        }
    }

    pub(crate) fn object_chunks_in(tx: &WriteTx<'_>, ino: Ino) -> Result<Vec<ChunkRef>, DbError> {
        let mut stmt = tx.conn().prepare(
            "SELECT chunk_no, chunk_hash, offset, len FROM object_chunks
             WHERE ino = ?1 ORDER BY chunk_no",
        )?;
        let mut rows = stmt.query([ino.as_slice()])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(chunk_ref_from_row(row)?);
        }
        Ok(out)
    }

    /// Read a chunk's bytes inside a write transaction.
    pub(crate) fn chunk_data_in(
        tx: &WriteTx<'_>,
        hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>, DbError> {
        let data: Option<Option<Vec<u8>>> = tx
            .conn()
            .query_row(
                "SELECT data FROM chunks WHERE hash = ?1",
                [hash.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(data.flatten())
    }

    /// Refresh `chunks.refcount` for the given hashes, using the client
    /// formula (object references plus outbox references).
    pub(crate) fn refresh_refcounts(tx: &WriteTx<'_>, hashes: &[[u8; 32]]) -> Result<(), DbError> {
        let mut seen: Vec<[u8; 32]> = hashes.to_vec();
        seen.sort_unstable();
        seen.dedup();
        let mut stmt = tx.conn().prepare(
            "UPDATE chunks SET refcount =
               (SELECT COUNT(*) FROM object_chunks oc WHERE oc.chunk_hash = chunks.hash)
             + (SELECT COUNT(*) FROM outbox_chunks x WHERE x.chunk_hash = chunks.hash)
             WHERE hash = ?1",
        )?;
        for hash in seen {
            stmt.execute([hash.as_slice()])?;
        }
        Ok(())
    }

    /// Store chunk bytes (or a lazy reference) and return its reference.
    pub(crate) fn put_chunk_ref(
        tx: &WriteTx<'_>,
        chunk_no: u32,
        data: &[u8],
    ) -> Result<ChunkRef, DbError> {
        let hash = sqlite::chunk_hash(data);
        let len = u32::try_from(data.len()).map_err(|_| DbError::Corrupt("chunk too large"))?;
        tx.put_chunk(hash, len, Some(data))?;
        Ok(ChunkRef {
            chunk_no,
            hash,
            offset: u64::from(chunk_no) * CHUNK,
            len,
        })
    }

    /// The canonical all-zero chunk of `len` bytes, stored once per length.
    pub(crate) fn zero_chunk(
        tx: &WriteTx<'_>,
        chunk_no: u32,
        len: u32,
    ) -> Result<ChunkRef, DbError> {
        let data = vec![0u8; len as usize];
        Self::put_chunk_ref(tx, chunk_no, &data)
    }

    /// Build a complete, contiguous chunk list for `size` bytes, taking the
    /// pieces that exist in `by_no` and zero-filling everything else.
    pub(crate) fn assemble_chunks(
        tx: &WriteTx<'_>,
        size: u64,
        by_no: &std::collections::BTreeMap<u32, ChunkRef>,
    ) -> Result<Vec<ChunkRef>, DbError> {
        let count = size.div_ceil(CHUNK);
        let mut out = Vec::with_capacity(count as usize);
        for chunk_no in 0..count {
            let chunk_no =
                u32::try_from(chunk_no).map_err(|_| DbError::Corrupt("too many chunks"))?;
            let expected_len = (size - u64::from(chunk_no) * CHUNK).min(CHUNK) as u32;
            let reference = match by_no.get(&chunk_no) {
                Some(existing) if existing.len == expected_len => existing.clone(),
                _ => Self::zero_chunk(tx, chunk_no, expected_len)?,
            };
            out.push(reference);
        }
        Ok(out)
    }
}

/// Background loop: PASSIVE checkpoint on the maintenance connection.
///
/// Polls a little faster than the interval so a WAL that crosses
/// `wal_bytes` between ticks is checkpointed early. PASSIVE never blocks the
/// writer or a reader; when a long read pins the WAL, the checkpoint simply
/// stops at the oldest snapshot and the next tick retries.
///
/// The same thread drains a pending state digest every
/// [`STATE_HASH_BACKGROUND`], so a small final batch does not leave
/// `meta.state_hash` behind the tree.
const STATE_HASH_BACKGROUND: Duration = Duration::from_secs(60);

fn checkpoint_loop(db: std::sync::Weak<ClientDb>, stop: Arc<AtomicBool>, config: CheckpointConfig) {
    let poll = Duration::from_millis(100).min(config.interval.max(Duration::from_millis(1)));
    let mut last = Instant::now();
    let mut last_hash = Instant::now();
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        std::thread::sleep(poll);
        let Some(db) = db.upgrade() else {
            return;
        };
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let due = last.elapsed() >= config.interval;
        let full = db.wal_bytes() > config.wal_bytes;
        if due || full {
            if let Err(error) = db.checkpoint_passive() {
                tracing::warn!(
                    event = "checkpoint",
                    error = %error,
                    "PASSIVE checkpoint failed; will retry"
                );
            }
            last = Instant::now();
        }
        if last_hash.elapsed() >= STATE_HASH_BACKGROUND {
            if let Err(error) = db.refresh_state_hash_pending() {
                tracing::warn!(
                    event = "state_hash",
                    error = %error,
                    "pending state digest refresh failed; will retry"
                );
            }
            last_hash = Instant::now();
        }
        db.reap_readers();
    }
}

impl Drop for ClientDb {
    fn drop(&mut self) {
        // A normal process exit commits what is still buffered. A crash does
        // not run this method; the volatile window is documented.
        self.stop_checkpoint();
        self.writeback.stop();
        if let Err(error) = self.writeback.flush_all(self) {
            tracing::warn!(
                event = "writeback_drop_flush",
                error = %error,
                "could not commit buffered writes while closing the client database"
            );
        }
    }
}

fn object_from_row(row: &rusqlite::Row<'_>) -> Result<Object, DbError> {
    object_from_row_offset(row, 0)
}

/// Read an `Object` starting at `offset` in `row`.
pub(crate) fn object_from_row_offset(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> Result<Object, DbError> {
    let bytes: Vec<u8> = row.get(offset)?;
    let ino: Ino = bytes
        .try_into()
        .map_err(|_| DbError::Corrupt("objects.ino is not 16 bytes"))?;
    let kind_text: String = row.get(offset + 1)?;
    let kind = ObjectKind::parse(&kind_text).ok_or(DbError::Corrupt("unknown object kind"))?;
    let mode: i64 = row.get(offset + 2)?;
    let uid: i64 = row.get(offset + 3)?;
    let gid: i64 = row.get(offset + 4)?;
    let mtime_ns: i64 = row.get(offset + 5)?;
    let size: i64 = row.get(offset + 6)?;
    let root: Vec<u8> = row.get(offset + 7)?;
    let file_root: [u8; 32] = root
        .try_into()
        .map_err(|_| DbError::Corrupt("file_root is not 32 bytes"))?;
    let block_count: i64 = row.get(offset + 8)?;
    let target: Option<Vec<u8>> = row.get(offset + 9)?;
    let nlink: i64 = row.get(offset + 10)?;
    let deleted: i64 = row.get(offset + 11)?;
    let created_seq: i64 = row.get(offset + 12)?;
    let updated_seq: i64 = row.get(offset + 13)?;
    Ok(Object {
        ino,
        kind,
        mode: u32::try_from(mode).map_err(|_| DbError::Corrupt("mode out of range"))?,
        uid: u32::try_from(uid).map_err(|_| DbError::Corrupt("uid out of range"))?,
        gid: u32::try_from(gid).map_err(|_| DbError::Corrupt("gid out of range"))?,
        mtime_ns,
        size: u64::try_from(size).map_err(|_| DbError::Corrupt("size out of range"))?,
        file_root,
        block_count: u32::try_from(block_count)
            .map_err(|_| DbError::Corrupt("block_count out of range"))?,
        target,
        nlink: u32::try_from(nlink).map_err(|_| DbError::Corrupt("nlink out of range"))?,
        deleted: deleted != 0,
        created_seq,
        updated_seq,
    })
}

fn chunk_ref_from_row(row: &rusqlite::Row<'_>) -> Result<ChunkRef, DbError> {
    let chunk_no: i64 = row.get(0)?;
    let bytes: Vec<u8> = row.get(1)?;
    let hash: [u8; 32] = bytes
        .try_into()
        .map_err(|_| DbError::Corrupt("chunk hash is not 32 bytes"))?;
    let offset: i64 = row.get(2)?;
    let len: i64 = row.get(3)?;
    Ok(ChunkRef {
        chunk_no: u32::try_from(chunk_no).map_err(|_| DbError::Corrupt("chunk_no out of range"))?,
        hash,
        offset: u64::try_from(offset).map_err(|_| DbError::Corrupt("chunk offset out of range"))?,
        len: u32::try_from(len).map_err(|_| DbError::Corrupt("chunk len out of range"))?,
    })
}

/// Split an absolute path into `(parent path, entry name)`.
///
/// `"/"` has no parent; `"/a"` is `("/", "a")`.
pub fn split_path(path: &str) -> Option<(&str, &str)> {
    if path == "/" || !path.starts_with('/') {
        return None;
    }
    match path.rfind('/') {
        Some(0) => Some(("/", &path[1..])),
        Some(index) => Some((&path[..index], &path[index + 1..])),
        None => None,
    }
}

/// Join a parent path and an entry name.
pub fn join_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// Current wall clock in nanoseconds, clamped at zero.
pub fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX)
        })
}

/// Everything the client database can refuse.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("another process holds the lock on {0}")]
    Locked(PathBuf),
    #[error("database belongs to a different cluster")]
    ClusterMismatch,
    #[error("corrupt database: {0}")]
    Corrupt(&'static str),
    #[error("chunk {} is not cached", hex::encode(.0))]
    MissingChunk([u8; 32]),
    #[error("{0}")]
    Errno(Errno),
}

impl DbError {
    /// The errno a FUSE callback must report.
    pub fn errno(&self) -> Errno {
        match self {
            Self::Errno(errno) => *errno,
            Self::MissingChunk(_) => Errno::EIO,
            Self::Store(_) | Self::Sqlite(_) | Self::Io(_) => Errno::EIO,
            Self::Locked(_) | Self::ClusterMismatch | Self::Corrupt(_) => Errno::EIO,
        }
    }
}

impl From<Errno> for DbError {
    fn from(value: Errno) -> Self {
        Self::Errno(value)
    }
}

impl From<DbError> for Errno {
    fn from(value: DbError) -> Self {
        value.errno()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::client::ops::CreateAttrs;
    use std::ffi::OsStr;

    fn open() -> (tempfile::TempDir, ClientDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = ClientDb::open(dir.path().join("client.db"), [7u8; 16]).unwrap();
        (dir, db)
    }

    #[tokio::test]
    async fn a_committed_outbox_row_wakes_the_uplink_once() {
        let (_dir, db) = open();
        // `initialize` commits once before any uplink exists. Drain that
        // permit so the assertions below observe only the calls they make.
        tokio::time::timeout(Duration::from_millis(10), db.uplink_notified())
            .await
            .expect("the open-time permit is retained");

        db.create_file(
            ROOT_INO,
            OsStr::new("f"),
            CreateAttrs::new(0o644, 1000, 1000),
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), db.uplink_notified())
            .await
            .expect("a local commit wakes the uplink");

        // A rollback appends no outbox row and must not wake the uplink.
        let failed: Result<(), DbError> = db.write(|_tx| Err(DbError::Corrupt("test rollback")));
        assert!(failed.is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), db.uplink_notified())
                .await
                .is_err(),
            "a rolled-back transaction must not publish a wakeup"
        );
    }

    #[test]
    fn a_pending_state_hash_is_drained_without_a_new_batch() {
        let (_dir, db) = open();
        let file = db
            .create_file(
                ROOT_INO,
                OsStr::new("f"),
                CreateAttrs::new(0o644, 1000, 1000),
            )
            .unwrap();
        db.write_at(file.ino, 0, b"hello").unwrap();
        let tree = db.read().unwrap().state_hash().unwrap();
        let stale = db.read().unwrap().meta_blob(keys::STATE_HASH).unwrap();
        assert_ne!(stale, tree.to_vec());

        // Make the time budget fresh so the next small batch stays pending.
        let now = sqlite::now_secs();
        db.write(|tx| {
            tx.set_meta_i64(keys::STATE_HASH_AT, now)?;
            tx.set_meta_i64(keys::STATE_HASH_PENDING, 0)?;
            Ok(())
        })
        .unwrap();
        db.write(|tx| {
            tx.set_meta_i64(keys::APPLIED_SEQ, 1)?;
            Ok(())
        })
        .unwrap();
        {
            let read = db.read().unwrap();
            assert_eq!(read.meta_i64(keys::STATE_HASH_PENDING).unwrap(), 1);
            assert_eq!(read.meta_blob(keys::STATE_HASH).unwrap(), stale);
        }

        assert!(db.refresh_state_hash_pending().unwrap());
        let read = db.read().unwrap();
        assert_eq!(read.meta_blob(keys::STATE_HASH).unwrap(), tree.to_vec());
        assert_eq!(read.meta_i64(keys::STATE_HASH_PENDING).unwrap(), 0);
    }

    #[test]
    fn create_write_read_roundtrip_and_durable_outbox() {
        let (dir, db) = open();
        let file = db
            .create_file(
                ROOT_INO,
                OsStr::new("f"),
                CreateAttrs::new(0o644, 1000, 1000),
            )
            .unwrap();
        assert_eq!(db.write_at(file.ino, 0, b"hello").unwrap(), 5);
        assert_eq!(db.read_at(file.ino, 0, 5).unwrap(), b"hello");
        let looked = db.lookup(ROOT_INO, OsStr::new("f")).unwrap();
        assert_eq!(looked.size, 5);
        assert_eq!(looked.nlink, 1);
        // The write is visible but still volatile.
        assert_eq!(db.outbox_count(OutboxState::Pending).unwrap(), 1);
        db.flush_all().unwrap();
        assert_eq!(db.outbox_count(OutboxState::Pending).unwrap(), 2);
        assert!(db.fuse_ino(file.ino).unwrap() >= 2);
        drop(db);

        // The outbox survives a restart: it is the local write intent.
        let path = dir.path().join("client.db");
        let again = ClientDb::open(&path, [7u8; 16]).unwrap();
        assert_eq!(again.outbox_count(OutboxState::Pending).unwrap(), 2);
        assert_eq!(again.read_at(file.ino, 0, 5).unwrap(), b"hello");
        assert_eq!(again.applied_seq().unwrap(), 0);
    }

    #[test]
    fn metadata_operations_update_the_tree() {
        let (dir, db) = open();
        let _ = dir;
        let sub = db
            .create_dir(ROOT_INO, OsStr::new("d"), CreateAttrs::new(0o755, 0, 0))
            .unwrap();
        let file = db
            .create_file(sub.ino, OsStr::new("f"), CreateAttrs::new(0o600, 0, 0))
            .unwrap();
        let names: Vec<String> = db
            .children(ROOT_INO)
            .unwrap()
            .into_iter()
            .map(|(name, _, _)| name)
            .collect();
        assert_eq!(names, vec!["d".to_owned()]);

        db.rename(
            ROOT_INO,
            OsStr::new("d"),
            ROOT_INO,
            OsStr::new("e"),
            Default::default(),
        )
        .unwrap();
        assert!(db.lookup(ROOT_INO, OsStr::new("d")).is_err());
        assert_eq!(db.lookup(ROOT_INO, OsStr::new("e")).unwrap().ino, sub.ino);
        assert_eq!(db.lookup(sub.ino, OsStr::new("f")).unwrap().ino, file.ino);
        assert_eq!(db.path_of(file.ino).unwrap(), "/e/f");

        db.unlink(sub.ino, OsStr::new("f")).unwrap();
        db.rmdir(ROOT_INO, OsStr::new("e")).unwrap();
        assert!(db.children(ROOT_INO).unwrap().is_empty());
    }

    #[test]
    fn rename_between_two_links_of_one_inode_is_a_no_op() {
        let (_dir, db) = open();
        let file = db
            .create_file(ROOT_INO, OsStr::new("a"), CreateAttrs::new(0o644, 0, 0))
            .unwrap();
        db.link(file.ino, ROOT_INO, OsStr::new("b")).unwrap();
        let before = db.outbox_count(OutboxState::Pending).unwrap();
        db.rename(
            ROOT_INO,
            OsStr::new("a"),
            ROOT_INO,
            OsStr::new("b"),
            Default::default(),
        )
        .unwrap();
        // POSIX keeps both names and reports success.
        assert_eq!(db.lookup(ROOT_INO, OsStr::new("a")).unwrap().ino, file.ino);
        assert_eq!(db.lookup(ROOT_INO, OsStr::new("b")).unwrap().ino, file.ino);
        assert_eq!(db.getattr(file.ino).unwrap().nlink, 2);
        assert_eq!(db.outbox_count(OutboxState::Pending).unwrap(), before);
    }

    #[test]
    fn rename_of_a_hard_link_names_the_renamed_entry() {
        let (_dir, db) = open();
        let file = db
            .create_file(ROOT_INO, OsStr::new("a"), CreateAttrs::new(0o644, 0, 0))
            .unwrap();
        db.link(file.ino, ROOT_INO, OsStr::new("b")).unwrap();
        db.rename(
            ROOT_INO,
            OsStr::new("b"),
            ROOT_INO,
            OsStr::new("c"),
            Default::default(),
        )
        .unwrap();
        assert_eq!(db.lookup(ROOT_INO, OsStr::new("c")).unwrap().ino, file.ino);
        let source: String = db
            .read()
            .unwrap()
            .conn()
            .query_row(
                "SELECT path FROM outbox WHERE kind = 'rename'
                  ORDER BY created_at DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        // The event must name /b, the entry that was renamed, not /a.
        assert_eq!(source, "/b");
    }

    #[test]
    fn a_sparse_writeback_commit_carries_a_contiguous_chunk_run() {
        let (_dir, db) = open();
        let file = db
            .create_file(
                ROOT_INO,
                OsStr::new("sparse"),
                CreateAttrs::new(0o644, 0, 0),
            )
            .unwrap();
        db.write_at(file.ino, 0, b"A").unwrap();
        db.write_at(file.ino, 200_000, b"B").unwrap();
        db.flush_all().unwrap();

        assert_eq!(db.getattr(file.ino).unwrap().size, 200_001);
        assert_eq!(db.read_at(file.ino, 0, 1).unwrap(), b"A");
        assert_eq!(db.read_at(file.ino, 199_999, 2).unwrap(), b"\0B");
        assert_eq!(db.read_at(file.ino, 1, 65_535).unwrap(), vec![0u8; 65_535]);

        let read = db.read().unwrap();
        let op_id: Vec<u8> = read
            .conn()
            .query_row(
                "SELECT op_id FROM outbox WHERE kind = 'write'
                  ORDER BY created_at DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut statement = read
            .conn()
            .prepare(
                "SELECT chunk_no, len FROM outbox_chunks
                  WHERE op_id = ?1 ORDER BY chunk_no",
            )
            .unwrap();
        let rows: Vec<(i64, i64)> = statement
            .query_map([op_id.as_slice()], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![(0, 65_536), (1, 65_536), (2, 65_536), (3, 3_393),]
        );
    }

    #[test]
    fn chunk_read_modify_write_and_truncate() {
        let (dir, db) = open();
        let _ = dir;
        let file = db
            .create_file(ROOT_INO, OsStr::new("big"), CreateAttrs::new(0o644, 0, 0))
            .unwrap();
        let data: Vec<u8> = (0..100_000u32).map(|value| value as u8).collect();
        db.write_at(file.ino, 0, &data).unwrap();
        assert_eq!(db.getattr(file.ino).unwrap().size, 100_000);
        assert_eq!(db.getattr(file.ino).unwrap().block_count, 2);
        assert_eq!(
            db.read_at(file.ino, 65_530, 20).unwrap(),
            &data[65_530..65_550]
        );

        // A partial overwrite inside the second chunk keeps the first intact.
        db.write_at(file.ino, 70_000, b"XYZ").unwrap();
        assert_eq!(db.read_at(file.ino, 69_998, 6).unwrap(), b"noXYZs");
        assert_eq!(db.read_at(file.ino, 0, 4).unwrap(), &data[..4]);

        db.truncate(file.ino, 70_001).unwrap();
        let object = db.getattr(file.ino).unwrap();
        assert_eq!(object.size, 70_001);
        assert_eq!(object.block_count, 2);
        assert_eq!(db.read_at(file.ino, 70_000, 10).unwrap(), b"X");

        db.truncate(file.ino, 0).unwrap();
        assert!(db.read_at(file.ino, 0, 10).unwrap().is_empty());
    }

    #[test]
    fn a_second_process_cannot_open_the_same_database() {
        let (dir, db) = open();
        let path = dir.path().join("client.db");
        let second = ClientDb::open(&path, [7u8; 16]);
        assert!(matches!(second, Err(DbError::Locked(_))));
        drop(db);
        assert!(ClientDb::open(&path, [7u8; 16]).is_ok());
    }

    #[test]
    fn a_different_cluster_is_refused() {
        let (dir, db) = open();
        drop(db);
        let error = ClientDb::open(dir.path().join("client.db"), [8u8; 16]);
        assert!(matches!(error, Err(DbError::ClusterMismatch)));
    }

    #[test]
    fn pooled_reads_reuse_a_connection_and_keep_their_snapshot() {
        let (_dir, db) = open();
        db.write(|tx| {
            tx.set_meta_i64("snapshot_probe", 1)?;
            Ok(())
        })
        .unwrap();
        let before = db.read().unwrap();
        assert_eq!(before.meta_i64("snapshot_probe").unwrap(), 1);
        db.write(|tx| {
            tx.set_meta_i64("snapshot_probe", 2)?;
            Ok(())
        })
        .unwrap();
        // The leased snapshot keeps the value it opened with.
        assert_eq!(before.meta_i64("snapshot_probe").unwrap(), 1);
        let stats = db.read_pool_stats();
        assert_eq!(stats.opens, 1, "the pool opened exactly one reader");
        assert_eq!(stats.live, 1);
        drop(before);
        // The returned connection is reused, and a new snapshot sees the
        // committed value.
        let after = db.read().unwrap();
        assert_eq!(after.meta_i64("snapshot_probe").unwrap(), 2);
        assert_eq!(db.read_pool_stats().opens, 1);
    }

    #[test]
    fn fsync_syncs_the_wal_without_checkpointing_it() {
        let dir = tempfile::tempdir().unwrap();
        let db = ClientDb::open_with_configs(
            dir.path().join("client.db"),
            [7u8; 16],
            WritebackConfig::default(),
            CheckpointConfig {
                interval: Duration::from_secs(3600),
                wal_bytes: u64::MAX,
            },
        )
        .unwrap();
        let file = db
            .create_file(ROOT_INO, OsStr::new("f"), CreateAttrs::new(0o644, 0, 0))
            .unwrap();
        db.write_at(file.ino, 0, &[7u8; 4096]).unwrap();
        db.fsync().unwrap();
        // The WAL still holds the commit: fsync must not truncate it.
        assert!(db.wal_bytes() > 0);
        assert_eq!(db.read_at(file.ino, 0, 4096).unwrap(), vec![7u8; 4096]);
        db.checkpoint_truncate().unwrap();
        assert_eq!(db.wal_bytes(), 0);
        assert_eq!(db.read_at(file.ino, 0, 4096).unwrap(), vec![7u8; 4096]);
    }

    #[test]
    fn a_passive_checkpoint_does_not_wait_for_a_long_read() {
        let dir = tempfile::tempdir().unwrap();
        let db = ClientDb::open_with_configs(
            dir.path().join("client.db"),
            [7u8; 16],
            WritebackConfig::default(),
            CheckpointConfig::default(),
        )
        .unwrap();
        // Hold a snapshot from before the write, so the checkpoint cannot
        // reset the WAL past it.
        let held = db.read().unwrap();
        let file = db
            .create_file(ROOT_INO, OsStr::new("f"), CreateAttrs::new(0o644, 0, 0))
            .unwrap();
        db.write_at(file.ino, 0, &[9u8; 4096]).unwrap();
        db.fsync().unwrap();
        let before = db.wal_bytes();
        assert!(before > 0);
        // `fsync` only syncs the WAL; an open snapshot cannot make it wait
        // for a checkpoint.
        let started = Instant::now();
        db.fsync().unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "fsync waited for the read snapshot"
        );
        db.checkpoint_passive().unwrap();
        // The read still pins its snapshot; the checkpoint returns anyway.
        assert!(db.wal_bytes() > 0);
        assert_eq!(held.meta_i64(keys::APPLIED_SEQ).unwrap(), 0);
        drop(held);
        db.checkpoint_truncate().unwrap();
        assert_eq!(db.wal_bytes(), 0);
    }

    #[test]
    fn a_passive_checkpoint_bounds_the_wal() {
        let dir = tempfile::tempdir().unwrap();
        let db = ClientDb::open_with_configs(
            dir.path().join("client.db"),
            [7u8; 16],
            WritebackConfig::default(),
            CheckpointConfig::default(),
        )
        .unwrap();
        let file = db
            .create_file(ROOT_INO, OsStr::new("f"), CreateAttrs::new(0o644, 0, 0))
            .unwrap();
        for round in 0..20u64 {
            let offset = round * 65_536;
            db.write_at(file.ino, offset, &[round as u8; 65_536])
                .unwrap();
            db.flush_all().unwrap();
            db.checkpoint_passive().unwrap();
        }
        // Without checkpoints this loop would leave ~1.3 MiB of WAL frames.
        assert!(
            db.wal_bytes() < 1024 * 1024,
            "WAL grew to {} bytes",
            db.wal_bytes()
        );
    }
}
