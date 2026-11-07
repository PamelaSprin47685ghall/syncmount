//! The client's only persistent state: one SQLite database.
//!
//! The mountpoint is a view over this database; it holds no file tree of its
//! own. Every FUSE callback either reads a snapshot ([`ClientDb::read`]) or
//! runs one `BEGIN IMMEDIATE` transaction ([`ClientDb::write`]) that updates
//! `objects`/`names`/`chunks`/`object_chunks` and appends the matching row to
//! the durable `outbox` in the same commit.
//!
//! # Why two handles
//!
//! `store::sqlite::Db::write` needs `&mut Db`; `Db::read` needs only `&Db` and
//! opens a fresh connection per call. One `Mutex<Db>` for writes and one for
//! the short "open a reader" step keeps a FUSE read from serialising behind a
//! large replay transaction.
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
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{OptionalExtension, params};
use rustix::fs::{FlockOperation, Mode, OFlags};

use crate::store::sqlite::{
    self, CHUNK_BYTES, ChunkRef, Db, EventKind, EventPayload, MetaValue, Object, ObjectKind, ROOT_INO,
    ReadTx, Role, StoreError, WriteTx, keys,
};
use crate::store::Errno;

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

/// The client database and its single-instance lock.
pub struct ClientDb {
    write: Mutex<Db>,
    reader: Mutex<Db>,
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
        rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|err| match err {
                rustix::io::Errno::WOULDBLOCK => DbError::Locked(path.clone()),
                other => DbError::Io(std::io::Error::from(other)),
            })?;

        let write = Db::open(&path, Role::Client)?;
        let reader = Db::open(&path, Role::Client)?;
        let store = Self {
            write: Mutex::new(write),
            reader: Mutex::new(reader),
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

    // -- transactions ------------------------------------------------------

    /// Open a consistent read snapshot. The lock is held only while the
    /// connection is created; the returned transaction is independent.
    pub fn read(&self) -> Result<ReadTx, DbError> {
        let db = self.lock_reader();
        Ok(db.read()?)
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
        Ok(value)
    }

    pub(crate) fn lock_writer(&self) -> MutexGuard<'_, Db> {
        self.write.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn lock_reader(&self) -> MutexGuard<'_, Db> {
        self.reader.lock().unwrap_or_else(PoisonError::into_inner)
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
        let name = name.to_str().ok_or(DbError::Errno(Errno::EINVAL))?;
        let tx = self.read()?;
        let entry = tx.name(parent, name)?.ok_or(DbError::Errno(Errno::ENOENT))?;
        let object = tx
            .object(entry.ino)?
            .ok_or(DbError::Errno(Errno::ENOENT))?;
        if object.deleted {
            return Err(DbError::Errno(Errno::ENOENT));
        }
        Ok(object)
    }

    /// Resolve an absolute path to its object.
    pub fn lookup_by_path(&self, path: &str) -> Result<Object, DbError> {
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
            let data = chunk
                .data
                .ok_or(DbError::MissingChunk(chunk_ref.hash))?;
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

    pub(crate) fn object_in_read(tx: &ReadTx, ino: Ino) -> Result<Option<Object>, DbError> {
        Ok(tx.object(ino)?)
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
    pub(crate) fn chunk_data_in(tx: &WriteTx<'_>, hash: [u8; 32]) -> Result<Option<Vec<u8>>, DbError> {
        let data: Option<Option<Vec<u8>>> = tx
            .conn()
            .query_row("SELECT data FROM chunks WHERE hash = ?1", [hash.as_slice()], |row| {
                row.get(0)
            })
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

    /// Store a chunk reference without bytes (a remote write whose stream has
    /// not arrived yet).
    pub(crate) fn put_chunk_ref_lazy(
        tx: &WriteTx<'_>,
        chunk_no: u32,
        hash: [u8; 32],
        len: u32,
    ) -> Result<ChunkRef, DbError> {
        tx.put_chunk(hash, len, None)?;
        Ok(ChunkRef {
            chunk_no,
            hash,
            offset: u64::from(chunk_no) * CHUNK,
            len,
        })
    }

    /// The canonical all-zero chunk of `len` bytes, stored once per length.
    pub(crate) fn zero_chunk(tx: &WriteTx<'_>, chunk_no: u32, len: u32) -> Result<ChunkRef, DbError> {
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
            let chunk_no = u32::try_from(chunk_no)
                .map_err(|_| DbError::Corrupt("too many chunks"))?;
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

    #[test]
    fn create_write_read_roundtrip_and_durable_outbox() {
        let (dir, db) = open();
        let file = db
            .create_file(ROOT_INO, OsStr::new("f"), CreateAttrs::new(0o644, 1000, 1000))
            .unwrap();
        assert_eq!(db.write_at(file.ino, 0, b"hello").unwrap(), 5);
        assert_eq!(db.read_at(file.ino, 0, 5).unwrap(), b"hello");
        let looked = db.lookup(ROOT_INO, OsStr::new("f")).unwrap();
        assert_eq!(looked.size, 5);
        assert_eq!(looked.nlink, 1);
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

        db.rename(ROOT_INO, OsStr::new("d"), ROOT_INO, OsStr::new("e"), Default::default())
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
        assert_eq!(db.read_at(file.ino, 65_530, 20).unwrap(), &data[65_530..65_550]);

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
}
