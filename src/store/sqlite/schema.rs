//! Core DDL, schema migration and the per-role tables.
//!
//! Both ends of the sync use the same core tables; only the role tables
//! differ. `PRAGMA user_version` is the migration cursor and
//! `meta.schema_version` mirrors it for the wire handshake.
//!
//! Every table is `STRICT` so a type mistake fails at the boundary instead of
//! being silently coerced. Every table is `WITHOUT ROWID` because each one has
//! a natural primary key and nothing needs a hidden rowid.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::hash;
use super::types::ObjectKind;
use super::{DEFAULT_EPOCH, Result, Role, SCHEMA_VERSION, StoreError, hash::file_root, meta_i64};

/// Bytes in one content chunk. Matches the transfer fragment size.
pub const CHUNK_BYTES: u32 = 65_536;

/// The root directory's 128-bit inode id. All zeroes, so it cannot collide
/// with an inode derived from a random 128-bit `op_id`.
pub const ROOT_INO: [u8; 16] = [0; 16];

/// Permission bits of the root directory (0755).
pub const ROOT_MODE: u32 = 0o755;

/// Link count of the root directory: itself plus the implicit `.` entry.
pub const ROOT_NLINK: u32 = 2;

/// Meta keys shared by both roles and by the role tables.
pub mod keys {
    /// Core schema version, mirrored from `PRAGMA user_version`.
    pub const SCHEMA_VERSION: &str = "schema_version";
    /// `client` or `server`; guards against opening a database as the wrong end.
    pub const ROLE: &str = "role";
    /// 16-byte cluster identity derived from the PSK. Written by the caller.
    pub const CLUSTER_ID: &str = "cluster_id";
    /// Current event epoch. Server: bumped by compaction. Client: last seen.
    pub const EPOCH: &str = "epoch";
    /// Server: last committed event sequence number.
    pub const SEQ: &str = "seq";
    /// Client: last applied server sequence number.
    pub const APPLIED_SEQ: &str = "applied_seq";
    /// Client: sequence number covered by the last local checkpoint.
    pub const COVERED_SEQ: &str = "covered_seq";
    /// Server: oldest sequence number still replayable.
    pub const REPLAY_FLOOR: &str = "replay_floor";
    /// Server: Unix seconds of the last compaction.
    pub const COMPACTED_AT: &str = "compacted_at";
    /// Server: `seq` immediately before the last compaction. A client whose
    /// `applied_seq` equals this value already holds the compacted state.
    pub const COMPACTED_FROM_SEQ: &str = "compacted_from_seq";
    /// Server: epoch produced by the last compaction.
    pub const COMPACTED_EPOCH: &str = "compacted_epoch";
    /// Server: last sequence of the compacted replay log. A fast-forwarding
    /// client adopts this as its new `applied_seq`.
    pub const COMPACTED_SEQ: &str = "compacted_seq";
    /// Server: 1 once the initial snapshot has been imported.
    pub const BOOTSTRAP_DONE: &str = "bootstrap_done";
    /// BLAKE3 state digest, see [`super::hash::state_hash`].
    pub const STATE_HASH: &str = "state_hash";
    /// Content chunk size; recorded so a future build can refuse a mismatch.
    pub const CHUNK_SIZE: &str = "chunk_size";
    /// Client: `full` or `lazy` chunk caching.
    pub const CACHE_MODE: &str = "cache_mode";
    /// Client: 1 when the outbox is non-empty or the replica is behind.
    pub const DIRTY: &str = "dirty";
    /// Client: next FUSE `st_ino` to hand out. Root is 1.
    pub const FUSE_INO_NEXT: &str = "fuse_ino_next";
    /// Client: Unix seconds of the last local checkpoint.
    pub const LAST_CHECKPOINT_AT: &str = "last_checkpoint_at";
}

/// Migration 1: the shared core tables.
const CORE_V1: &str = r#"
CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value ANY NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE objects (
  ino         BLOB PRIMARY KEY CHECK (length(ino) = 16),
  kind        TEXT NOT NULL CHECK (kind IN
                ('file','dir','symlink','char','block','fifo','socket')),
  mode        INTEGER NOT NULL CHECK (mode BETWEEN 0 AND 4294967295),
  uid         INTEGER NOT NULL CHECK (uid BETWEEN 0 AND 4294967295),
  gid         INTEGER NOT NULL CHECK (gid BETWEEN 0 AND 4294967295),
  mtime_ns    INTEGER NOT NULL CHECK (mtime_ns >= 0),
  size        INTEGER NOT NULL CHECK (size >= 0),
  file_root   BLOB NOT NULL CHECK (length(file_root) = 32),
  block_count INTEGER NOT NULL CHECK (block_count >= 0),
  target      BLOB,
  nlink       INTEGER NOT NULL DEFAULT 1 CHECK (nlink >= 0),
  deleted     INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0,1)),
  created_seq INTEGER NOT NULL DEFAULT 0 CHECK (created_seq >= 0),
  updated_seq INTEGER NOT NULL DEFAULT 0 CHECK (updated_seq >= 0),
  CHECK (kind =  'symlink' OR target IS NULL),
  CHECK (kind <> 'symlink' OR target IS NOT NULL),
  CHECK (deleted = 0 OR nlink = 0)
) STRICT, WITHOUT ROWID;

CREATE TABLE names (
  parent BLOB NOT NULL CHECK (length(parent) = 16),
  name   TEXT NOT NULL CHECK (
           length(name) BETWEEN 1 AND 255
           AND name <> '.' AND name <> '..'
           AND instr(name, '/') = 0),
  ino    BLOB NOT NULL CHECK (length(ino) = 16),
  path   TEXT NOT NULL CHECK (
           path <> '/'
           AND substr(path, 1, 1) = '/'
           AND length(CAST(path AS BLOB)) <= 4096),
  PRIMARY KEY (parent, name),
  UNIQUE (path),
  FOREIGN KEY (parent) REFERENCES objects(ino)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  FOREIGN KEY (ino) REFERENCES objects(ino)
    ON UPDATE CASCADE ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

-- Content-addressed chunks. The server always stores data; a client may know
-- only the hash (lazy cache) and fill the bytes in later.
CREATE TABLE chunks (
  hash     BLOB PRIMARY KEY CHECK (length(hash) = 32),
  len      INTEGER NOT NULL CHECK (len BETWEEN 0 AND 65536),
  data     BLOB,
  refcount INTEGER NOT NULL DEFAULT 0 CHECK (refcount >= 0),
  CHECK (data IS NULL OR length(data) = len)
) STRICT, WITHOUT ROWID;

-- Current file content = ordered list of chunks.
CREATE TABLE object_chunks (
  ino        BLOB NOT NULL CHECK (length(ino) = 16),
  chunk_no   INTEGER NOT NULL CHECK (chunk_no >= 0),
  chunk_hash BLOB NOT NULL CHECK (length(chunk_hash) = 32),
  offset     INTEGER NOT NULL CHECK (offset >= 0),
  len        INTEGER NOT NULL CHECK (len BETWEEN 0 AND 65536),
  PRIMARY KEY (ino, chunk_no),
  FOREIGN KEY (ino) REFERENCES objects(ino) ON DELETE CASCADE,
  FOREIGN KEY (chunk_hash) REFERENCES chunks(hash) ON DELETE RESTRICT,
  CHECK (offset = chunk_no * 65536)
) STRICT, WITHOUT ROWID;

CREATE TABLE events (
  seq        INTEGER PRIMARY KEY CHECK (seq > 0),
  epoch      INTEGER NOT NULL CHECK (epoch >= 1),
  op_id      BLOB CHECK (op_id IS NULL OR length(op_id) = 16),
  session_id BLOB CHECK (session_id IS NULL OR length(session_id) = 16),
  kind       TEXT NOT NULL CHECK (kind IN (
               'create_file','create_dir','symlink','write','truncate',
               'setattr','rename','unlink','rmdir','link',
               'lock','unlock','leave','sync_ctrl')),
  path       TEXT,
  path2      TEXT,
  ino        BLOB CHECK (ino IS NULL OR length(ino) = 16),
  payload    BLOB NOT NULL,
  result     TEXT NOT NULL DEFAULT 'ok',
  applied    INTEGER NOT NULL DEFAULT 1 CHECK (applied IN (0,1)),
  created_at INTEGER NOT NULL,
  CHECK (op_id IS NOT NULL OR kind = 'leave')
) STRICT, WITHOUT ROWID;

CREATE INDEX names_ino ON names(ino);
CREATE INDEX object_chunks_hash ON object_chunks(chunk_hash);
CREATE UNIQUE INDEX events_op_id ON events(op_id) WHERE op_id IS NOT NULL;
CREATE INDEX events_epoch_seq ON events(epoch, seq);
"#;

/// Client-only tables: unconfirmed local operations, session locks and the
/// local FUSE inode view.
const CLIENT_TABLES: &str = r#"
CREATE TABLE IF NOT EXISTS outbox (
  op_id      BLOB PRIMARY KEY CHECK (length(op_id) = 16),
  kind       TEXT NOT NULL,
  path       TEXT,
  path2      TEXT,
  ino        BLOB CHECK (ino IS NULL OR length(ino) = 16),
  payload    BLOB NOT NULL,
  undo       BLOB,
  state      TEXT NOT NULL CHECK (state IN ('pending','sent','acked','failed')),
  attempts   INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS outbox_chunks (
  op_id      BLOB NOT NULL CHECK (length(op_id) = 16),
  chunk_no   INTEGER NOT NULL,
  chunk_hash BLOB NOT NULL CHECK (length(chunk_hash) = 32),
  offset     INTEGER NOT NULL,
  len        INTEGER NOT NULL,
  PRIMARY KEY (op_id, chunk_no),
  FOREIGN KEY (op_id) REFERENCES outbox(op_id) ON DELETE CASCADE,
  FOREIGN KEY (chunk_hash) REFERENCES chunks(hash) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS locks (
  session_id BLOB NOT NULL CHECK (length(session_id) = 16),
  ino        BLOB NOT NULL CHECK (length(ino) = 16),
  start      INTEGER NOT NULL,
  len        INTEGER NOT NULL,
  exclusive  INTEGER NOT NULL CHECK (exclusive IN (0,1)),
  PRIMARY KEY (session_id, ino, start, len)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS fuse_inos (
  ino      BLOB PRIMARY KEY CHECK (length(ino) = 16),
  fuse_ino INTEGER NOT NULL UNIQUE
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS outbox_state ON outbox(state, created_at);
CREATE INDEX IF NOT EXISTS outbox_chunks_hash ON outbox_chunks(chunk_hash);
"#;

/// Server-only tables: global op deduplication and the chunks an event
/// introduced.
const SERVER_TABLES: &str = r#"
CREATE TABLE IF NOT EXISTS op_ids (
  op_id        BLOB PRIMARY KEY CHECK (length(op_id) = 16),
  payload_hash BLOB NOT NULL CHECK (length(payload_hash) = 32),
  first_seq    INTEGER NOT NULL,
  seen_at      INTEGER NOT NULL,
  FOREIGN KEY (first_seq) REFERENCES events(seq) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS event_chunks (
  seq        INTEGER NOT NULL,
  chunk_no   INTEGER NOT NULL,
  chunk_hash BLOB NOT NULL CHECK (length(chunk_hash) = 32),
  offset     INTEGER NOT NULL,
  len        INTEGER NOT NULL,
  PRIMARY KEY (seq, chunk_no),
  FOREIGN KEY (seq) REFERENCES events(seq) ON DELETE CASCADE,
  FOREIGN KEY (chunk_hash) REFERENCES chunks(hash) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS op_ids_first_seq ON op_ids(first_seq);
CREATE INDEX IF NOT EXISTS event_chunks_hash ON event_chunks(chunk_hash);

CREATE TRIGGER IF NOT EXISTS chunks_require_data
BEFORE INSERT ON chunks
WHEN NEW.data IS NULL
BEGIN SELECT RAISE(ABORT, 'server chunk data required'); END;

CREATE TRIGGER IF NOT EXISTS chunks_keep_data
BEFORE UPDATE OF data ON chunks
WHEN NEW.data IS NULL
BEGIN SELECT RAISE(ABORT, 'server chunk data required'); END;
"#;

/// Open-time migration. Runs in one immediate transaction so two processes
/// racing to create the same file cannot both apply migration 1.
pub(crate) fn migrate(conn: &mut Connection, requested: Role) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    let current: i64 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if current > SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchema {
            found: current,
            supported: SCHEMA_VERSION,
        });
    }
    if current < 1 {
        tx.execute_batch(CORE_V1)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    }

    let stored = match tx
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            [keys::ROLE],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        Some(text) => {
            Role::parse(&text).ok_or(StoreError::Corrupt("meta.role is not a known role"))?
        }
        None => {
            tx.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)",
                params![keys::ROLE, requested.as_str()],
            )?;
            requested
        }
    };
    if stored != requested {
        return Err(StoreError::RoleMismatch { stored, requested });
    }

    ensure_role_schema(&tx, stored)?;
    ensure_root(&tx)?;
    ensure_defaults(&tx, stored)?;

    let chunk_size = meta_i64(&tx, keys::CHUNK_SIZE)?;
    if chunk_size != i64::from(CHUNK_BYTES) {
        return Err(StoreError::ChunkSizeMismatch {
            stored: chunk_size,
            supported: i64::from(CHUNK_BYTES),
        });
    }

    tx.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![keys::SCHEMA_VERSION, SCHEMA_VERSION],
    )?;

    tx.commit()?;
    Ok(())
}

fn ensure_role_schema(conn: &Connection, role: Role) -> Result<()> {
    let ddl = match role {
        Role::Client => CLIENT_TABLES,
        Role::Server => SERVER_TABLES,
    };
    conn.execute_batch(ddl)?;
    Ok(())
}

/// Insert the root object exactly once. The root is implicit in the tree (it
/// has no `names` row), so it must exist before any child can be linked.
fn ensure_root(conn: &Connection) -> Result<()> {
    let existing = conn
        .query_row(
            "SELECT kind FROM objects WHERE ino = ?1",
            [ROOT_INO.as_slice()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    match existing {
        Some(kind) if kind != ObjectKind::Dir.as_str() => {
            Err(StoreError::Corrupt("root object is not a directory"))
        }
        Some(_) => Ok(()),
        None => {
            let dir_root = file_root(ObjectKind::Dir, None, &[]);
            conn.execute(
                "INSERT INTO objects
                   (ino, kind, mode, uid, gid, mtime_ns, size, file_root,
                    block_count, target, nlink, deleted, created_seq, updated_seq)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    ROOT_INO.as_slice(),
                    ObjectKind::Dir.as_str(),
                    i64::from(ROOT_MODE),
                    0i64,
                    0i64,
                    0i64,
                    0i64,
                    dir_root.as_slice(),
                    0i64,
                    Option::<&[u8]>::None,
                    i64::from(ROOT_NLINK),
                    0i64,
                    0i64,
                    0i64,
                ],
            )?;
            Ok(())
        }
    }
}

fn ensure_defaults(conn: &Connection, role: Role) -> Result<()> {
    const SERVER_DEFAULTS: [(&str, i64); 4] = [
        (keys::SEQ, 0),
        (keys::REPLAY_FLOOR, 1),
        (keys::BOOTSTRAP_DONE, 0),
        (keys::COMPACTED_AT, 0),
    ];
    const CLIENT_DEFAULTS: [(&str, i64); 5] = [
        (keys::APPLIED_SEQ, 0),
        (keys::COVERED_SEQ, 0),
        (keys::DIRTY, 0),
        (keys::FUSE_INO_NEXT, 2),
        (keys::LAST_CHECKPOINT_AT, 0),
    ];

    let common: [(&str, i64); 2] = [
        (keys::EPOCH, DEFAULT_EPOCH),
        (keys::CHUNK_SIZE, i64::from(CHUNK_BYTES)),
    ];
    for (key, value) in common {
        conn.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
    }

    let role_defaults: &[(&str, i64)] = match role {
        Role::Server => &SERVER_DEFAULTS,
        Role::Client => &CLIENT_DEFAULTS,
    };
    for &(key, value) in role_defaults {
        conn.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
    }

    if role == Role::Client {
        conn.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES (?1, ?2)",
            params![keys::CACHE_MODE, "full"],
        )?;
    }

    let has_hash = conn
        .query_row(
            "SELECT 1 FROM meta WHERE key = ?1",
            [keys::STATE_HASH],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some();
    if !has_hash {
        let state = hash::state_hash(conn)?;
        conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)",
            params![keys::STATE_HASH, state.as_slice()],
        )?;
    }

    Ok(())
}
