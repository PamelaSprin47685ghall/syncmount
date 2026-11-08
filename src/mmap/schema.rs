//! mm database DDL, migration and open-time configuration.
//!
//! The mm database is a separate SQLite file per namespace. It never shares a
//! file, a table, a sequence or a migration cursor with the 1.0 database, so
//! compaction and `state_hash` in 1.0 cannot observe mm rows.
//!
//! # Tables
//!
//! ```text
//! mm_meta         one row: namespace, role, epoch, mm_seq, chunk size
//! mm_dirs         one row per directory: path, base triple, phase, attrs
//! mm_files        one row per direct entry: name, kind, attrs, current version
//! mm_versions     immutable content versions: size, file_root, content_hash
//! mm_chunks       content-addressed 64 KiB chunks
//! mm_version_chunks  ordered chunk list of one version
//! mm_base         last committed direct-entry snapshot of one directory
//! mm_uploads      upload sessions and their spool paths
//! mm_batches      immutable commit log, one row per committed batch
//! mm_locks        per-directory upload leases
//! mm_dir_versions authoritative per-directory base (dir_seq, dir_version)
//! ```
//!
//! Every table is `STRICT`. All key tables are `WITHOUT ROWID`; each has a
//! natural primary key and nothing needs a hidden rowid.

use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::base;
use super::types::{CHUNK_BYTES, DirAttrs, MmRole, Phase, ROOT_INO, ROOT_MODE};
use super::{MmError, now_ms};

/// Migration cursor stored in `PRAGMA user_version`.
pub const MM_SCHEMA_VERSION: i64 = 1;

/// First epoch of a fresh mm database.
pub const DEFAULT_EPOCH: u64 = 1;

/// Global sequence before the first committed batch.
pub const DEFAULT_MM_SEQ: u64 = 0;

/// SQLite busy timeout used by every connection.
pub const BUSY_TIMEOUT_MS: u64 = 5_000;

/// Migration 1: every mm table and index.
const MM_SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS mm_meta (
  id            INTEGER PRIMARY KEY CHECK (id = 0),
  namespace     TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('server','client')),
  epoch         INTEGER NOT NULL CHECK (epoch >= 1),
  mm_seq        INTEGER NOT NULL CHECK (mm_seq >= 0),
  chunk_size    INTEGER NOT NULL CHECK (chunk_size = 65536),
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS mm_dirs (
  namespace     TEXT NOT NULL,
  ino           BLOB NOT NULL CHECK (length(ino) = 16),
  path          TEXT NOT NULL CHECK (
                  substr(path, 1, 1) = '/'
                  AND length(CAST(path AS BLOB)) <= 4096
                  AND instr(path, '//') = 0
                  AND (path = '/' OR substr(path, -1, 1) <> '/')
                  AND instr(path, '/./') = 0
                  AND instr(path, '/../') = 0
                  AND path <> '/.'
                  AND path <> '/..'
                  AND path NOT LIKE '%/..'
                  AND path NOT LIKE '%/.'),
  base_epoch    INTEGER NOT NULL CHECK (base_epoch >= 1),
  base_seq      INTEGER NOT NULL CHECK (base_seq >= 0),
  dir_version   BLOB NOT NULL CHECK (length(dir_version) = 32),
  phase         TEXT NOT NULL CHECK (
                  phase IN ('absent','manifest','checking_out','ready','stale','failed')),
  mode          INTEGER NOT NULL CHECK (mode BETWEEN 0 AND 4294967295),
  uid           INTEGER NOT NULL CHECK (uid BETWEEN 0 AND 4294967295),
  gid           INTEGER NOT NULL CHECK (gid BETWEEN 0 AND 4294967295),
  mtime_ns      INTEGER NOT NULL CHECK (mtime_ns >= 0),
  deleted       INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0,1)),
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, ino),
  UNIQUE (namespace, path)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS mm_files (
  namespace     TEXT NOT NULL,
  ino           BLOB NOT NULL CHECK (length(ino) = 16),
  dir_ino       BLOB NOT NULL CHECK (length(dir_ino) = 16),
  name          TEXT NOT NULL CHECK (
                  length(CAST(name AS BLOB)) BETWEEN 1 AND 255
                  AND name <> '.' AND name <> '..'
                  AND instr(name, '/') = 0),
  kind          TEXT NOT NULL CHECK (kind IN ('file','symlink','dir')),
  mode          INTEGER NOT NULL CHECK (mode BETWEEN 0 AND 4294967295),
  uid           INTEGER NOT NULL CHECK (uid BETWEEN 0 AND 4294967295),
  gid           INTEGER NOT NULL CHECK (gid BETWEEN 0 AND 4294967295),
  mtime_ns      INTEGER NOT NULL CHECK (mtime_ns >= 0),
  size          INTEGER NOT NULL CHECK (size >= 0),
  file_root     BLOB NOT NULL CHECK (length(file_root) = 32),
  content_hash  BLOB CHECK (content_hash IS NULL OR length(content_hash) = 32),
  target        BLOB,
  version       INTEGER NOT NULL CHECK (version >= 0),
  deleted       INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0,1)),
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, ino),
  UNIQUE (namespace, dir_ino, name),
  FOREIGN KEY (namespace, dir_ino) REFERENCES mm_dirs(namespace, ino) ON DELETE CASCADE,
  CHECK (kind <> 'symlink' OR target IS NOT NULL),
  CHECK (kind = 'symlink' OR target IS NULL),
  CHECK (kind <> 'file' OR content_hash IS NOT NULL),
  CHECK (kind = 'file' OR content_hash IS NULL),
  CHECK (kind <> 'dir' OR size = 0),
  CHECK (kind <> 'dir' OR version = 0),
  CHECK (kind = 'dir' OR version >= 1)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS mm_chunks (
  hash     BLOB PRIMARY KEY CHECK (length(hash) = 32),
  len      INTEGER NOT NULL CHECK (len BETWEEN 1 AND 65536),
  data     BLOB NOT NULL CHECK (length(data) = len),
  refcount INTEGER NOT NULL DEFAULT 0 CHECK (refcount >= 0)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS mm_versions (
  namespace     TEXT NOT NULL,
  ino           BLOB NOT NULL CHECK (length(ino) = 16),
  version       INTEGER NOT NULL CHECK (version >= 1),
  size          INTEGER NOT NULL CHECK (size >= 0),
  file_root     BLOB NOT NULL CHECK (length(file_root) = 32),
  content_hash  BLOB NOT NULL CHECK (length(content_hash) = 32),
  chunk_count   INTEGER NOT NULL CHECK (chunk_count >= 0),
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, ino, version),
  FOREIGN KEY (namespace, ino) REFERENCES mm_files(namespace, ino) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS mm_version_chunks (
  namespace  TEXT NOT NULL,
  ino        BLOB NOT NULL CHECK (length(ino) = 16),
  version    INTEGER NOT NULL CHECK (version >= 1),
  chunk_no   INTEGER NOT NULL CHECK (chunk_no >= 0),
  chunk_hash BLOB NOT NULL CHECK (length(chunk_hash) = 32),
  offset     INTEGER NOT NULL CHECK (offset >= 0),
  len        INTEGER NOT NULL CHECK (len BETWEEN 1 AND 65536),
  PRIMARY KEY (namespace, ino, version, chunk_no),
  FOREIGN KEY (namespace, ino, version)
    REFERENCES mm_versions(namespace, ino, version) ON DELETE CASCADE,
  FOREIGN KEY (chunk_hash) REFERENCES mm_chunks(hash) ON DELETE RESTRICT,
  CHECK (offset = chunk_no * 65536)
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS mm_version_chunks_hash
  ON mm_version_chunks(chunk_hash);
CREATE INDEX IF NOT EXISTS mm_versions_root
  ON mm_versions(namespace, ino, file_root);

CREATE TABLE IF NOT EXISTS mm_base (
  namespace    TEXT NOT NULL,
  dir_ino      BLOB NOT NULL CHECK (length(dir_ino) = 16),
  name         TEXT NOT NULL CHECK (
                 length(CAST(name AS BLOB)) BETWEEN 1 AND 255
                 AND name <> '.' AND name <> '..'
                 AND instr(name, '/') = 0),
  ino          BLOB NOT NULL CHECK (length(ino) = 16),
  kind         TEXT NOT NULL CHECK (kind IN ('file','symlink','dir')),
  mode         INTEGER NOT NULL CHECK (mode BETWEEN 0 AND 4294967295),
  uid          INTEGER NOT NULL CHECK (uid BETWEEN 0 AND 4294967295),
  gid          INTEGER NOT NULL CHECK (gid BETWEEN 0 AND 4294967295),
  mtime_ns     INTEGER NOT NULL CHECK (mtime_ns >= 0),
  size         INTEGER NOT NULL CHECK (size >= 0),
  file_root    BLOB NOT NULL CHECK (length(file_root) = 32),
  content_hash BLOB CHECK (content_hash IS NULL OR length(content_hash) = 32),
  target       BLOB,
  PRIMARY KEY (namespace, dir_ino, name),
  FOREIGN KEY (namespace, dir_ino) REFERENCES mm_dirs(namespace, ino) ON DELETE CASCADE,
  CHECK (kind <> 'symlink' OR target IS NOT NULL),
  CHECK (kind = 'symlink' OR target IS NULL),
  CHECK (kind = 'file' OR content_hash IS NULL)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS mm_uploads (
  namespace      TEXT NOT NULL,
  batch_id       BLOB NOT NULL CHECK (length(batch_id) = 16),
  lock_id        BLOB NOT NULL CHECK (length(lock_id) = 16),
  dir_path       TEXT NOT NULL,
  dir_ino        BLOB NOT NULL CHECK (length(dir_ino) = 16),
  base_epoch     INTEGER NOT NULL CHECK (base_epoch >= 1),
  base_seq       INTEGER NOT NULL CHECK (base_seq >= 0),
  dir_version    BLOB NOT NULL CHECK (length(dir_version) = 32),
  manifest_hash  BLOB NOT NULL CHECK (length(manifest_hash) = 32),
  state          TEXT NOT NULL CHECK (state IN ('open','uploading','verified','aborted')),
  spool_path     TEXT NOT NULL,
  bytes_received INTEGER NOT NULL DEFAULT 0 CHECK (bytes_received >= 0),
  created_at_ms  INTEGER NOT NULL,
  updated_at_ms  INTEGER NOT NULL,
  expires_at_ms  INTEGER NOT NULL,
  PRIMARY KEY (namespace, batch_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS mm_uploads_lock
  ON mm_uploads(namespace, lock_id);
CREATE INDEX IF NOT EXISTS mm_uploads_expiry
  ON mm_uploads(namespace, expires_at_ms);

CREATE TABLE IF NOT EXISTS mm_batches (
  namespace           TEXT NOT NULL,
  batch_id            BLOB NOT NULL CHECK (length(batch_id) = 16),
  dir_path            TEXT NOT NULL,
  dir_ino             BLOB NOT NULL CHECK (length(dir_ino) = 16),
  base_epoch          INTEGER NOT NULL CHECK (base_epoch >= 1),
  base_seq            INTEGER NOT NULL CHECK (base_seq >= 0),
  base_seq_after      INTEGER NOT NULL CHECK (base_seq_after >= 0),
  snapshot_seq        INTEGER NOT NULL CHECK (snapshot_seq >= 0),
  dir_version_before  BLOB NOT NULL CHECK (length(dir_version_before) = 32),
  dir_version_after   BLOB NOT NULL CHECK (length(dir_version_after) = 32),
  manifest_hash       BLOB NOT NULL CHECK (length(manifest_hash) = 32),
  client_id           BLOB NOT NULL CHECK (length(client_id) = 16),
  entry_count         INTEGER NOT NULL CHECK (entry_count >= 0),
  bytes               INTEGER NOT NULL CHECK (bytes >= 0),
  committed_at_ms     INTEGER NOT NULL,
  PRIMARY KEY (namespace, batch_id)
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX IF NOT EXISTS mm_batches_snapshot
  ON mm_batches(namespace, snapshot_seq);
CREATE INDEX IF NOT EXISTS mm_batches_dir
  ON mm_batches(namespace, dir_ino, snapshot_seq);

CREATE TABLE IF NOT EXISTS mm_locks (
  namespace      TEXT NOT NULL,
  dir_path       TEXT NOT NULL,
  dir_ino        BLOB NOT NULL CHECK (length(dir_ino) = 16),
  lock_id        BLOB NOT NULL CHECK (length(lock_id) = 16),
  owner_client   BLOB NOT NULL CHECK (length(owner_client) = 16),
  owner_session  BLOB NOT NULL CHECK (length(owner_session) = 16),
  base_epoch     INTEGER NOT NULL CHECK (base_epoch >= 1),
  base_seq       INTEGER NOT NULL CHECK (base_seq >= 0),
  batch_id       BLOB CHECK (batch_id IS NULL OR length(batch_id) = 16),
  expires_at_ms  INTEGER NOT NULL,
  created_at_ms  INTEGER NOT NULL,
  renewed_at_ms  INTEGER NOT NULL,
  progress_bytes INTEGER NOT NULL DEFAULT 0 CHECK (progress_bytes >= 0),
  PRIMARY KEY (namespace, dir_path)
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX IF NOT EXISTS mm_locks_id
  ON mm_locks(namespace, lock_id);

CREATE TABLE IF NOT EXISTS mm_dir_versions (
  namespace    TEXT NOT NULL,
  dir_ino      BLOB NOT NULL CHECK (length(dir_ino) = 16),
  dir_path     TEXT NOT NULL,
  base_epoch   INTEGER NOT NULL CHECK (base_epoch >= 1),
  dir_seq      INTEGER NOT NULL CHECK (dir_seq >= 0),
  snapshot_seq INTEGER NOT NULL CHECK (snapshot_seq >= 0),
  dir_version  BLOB NOT NULL CHECK (length(dir_version) = 32),
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, dir_ino),
  FOREIGN KEY (namespace, dir_ino) REFERENCES mm_dirs(namespace, ino) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;
"#;

/// Apply open-time pragmas.
///
/// WAL is mandatory: a reader must see a consistent snapshot while the single
/// writer commits. The server uses `synchronous=FULL` because a confirmed
/// batch must survive a power loss; a client shadow is rebuildable and uses
/// `NORMAL`, matching the 1.0 split.
pub(crate) fn configure(conn: &Connection, role: MmRole) -> Result<(), MmError> {
    conn.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
    let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(MmError::NotWal { mode });
    }
    let synchronous = match role {
        MmRole::Server => "FULL",
        MmRole::Client => "NORMAL",
    };
    conn.execute_batch(&format!(
        "PRAGMA synchronous = {synchronous}; PRAGMA foreign_keys = ON;"
    ))?;
    Ok(())
}

/// Migrate the mm schema and ensure the root directory exists.
///
/// The whole migration runs in one immediate transaction so two processes
/// racing to create the same file cannot both apply migration 1.
pub(crate) fn migrate(conn: &mut Connection, role: MmRole, namespace: &str) -> Result<(), MmError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    let current: i64 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if current > MM_SCHEMA_VERSION {
        return Err(MmError::UnsupportedSchema {
            found: current,
            supported: MM_SCHEMA_VERSION,
        });
    }
    if current < 1 {
        tx.execute_batch(MM_SCHEMA_V1)?;
        tx.pragma_update(None, "user_version", MM_SCHEMA_VERSION)?;
    }

    ensure_meta(&tx, role, namespace)?;
    ensure_root(&tx, namespace)?;

    tx.commit()?;
    Ok(())
}

fn ensure_meta(conn: &Connection, role: MmRole, namespace: &str) -> Result<(), MmError> {
    let stored = conn
        .query_row(
            "SELECT namespace, role, chunk_size FROM mm_meta WHERE id = 0",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    match stored {
        Some((stored_namespace, stored_role, chunk_size)) => {
            if stored_namespace != namespace {
                return Err(MmError::NamespaceMismatch {
                    stored: stored_namespace,
                    requested: namespace.to_owned(),
                });
            }
            let stored_role = MmRole::parse(&stored_role)
                .ok_or(MmError::Corrupt("mm_meta.role is not a known role"))?;
            if stored_role != role {
                return Err(MmError::RoleMismatch {
                    stored: stored_role,
                    requested: role,
                });
            }
            if chunk_size != i64::from(CHUNK_BYTES) {
                return Err(MmError::Corrupt("mm chunk size mismatch"));
            }
        }
        None => {
            let now = now_ms();
            conn.execute(
                "INSERT INTO mm_meta
                   (id, namespace, role, epoch, mm_seq, chunk_size, created_at_ms, updated_at_ms)
                 VALUES (0, ?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                params![
                    namespace,
                    role.as_str(),
                    i64::try_from(DEFAULT_EPOCH)
                        .map_err(|_| MmError::Corrupt("epoch does not fit i64"))?,
                    i64::try_from(DEFAULT_MM_SEQ)
                        .map_err(|_| MmError::Corrupt("mm_seq does not fit i64"))?,
                    i64::from(CHUNK_BYTES),
                    now,
                ],
            )?;
        }
    }
    Ok(())
}

fn ensure_root(conn: &Connection, namespace: &str) -> Result<(), MmError> {
    let existing = conn
        .query_row(
            "SELECT path, deleted FROM mm_dirs WHERE namespace = ?1 AND ino = ?2",
            params![namespace, ROOT_INO.as_slice()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    if let Some((path, deleted)) = existing {
        if path != "/" || deleted != 0 {
            return Err(MmError::Corrupt("root directory is missing or deleted"));
        }
        return Ok(());
    }

    let epoch: i64 = conn.query_row("SELECT epoch FROM mm_meta WHERE id = 0", [], |row| {
        row.get(0)
    })?;
    let attrs = DirAttrs {
        mode: ROOT_MODE,
        uid: 0,
        gid: 0,
        mtime_ns: 0,
    };
    let version = base::dir_version(namespace, ROOT_INO, &attrs, &[]);
    let now = now_ms();
    conn.execute(
        "INSERT INTO mm_dirs
           (namespace, ino, path, base_epoch, base_seq, dir_version, phase,
            mode, uid, gid, mtime_ns, deleted, created_at_ms, updated_at_ms)
         VALUES (?1, ?2, '/', ?3, 1, ?4, ?5, ?6, 0, 0, 0, 0, ?7, ?7)",
        params![
            namespace,
            ROOT_INO.as_slice(),
            epoch,
            version.as_slice(),
            Phase::Ready.as_str(),
            i64::from(ROOT_MODE),
            now,
        ],
    )?;
    conn.execute(
        "INSERT INTO mm_dir_versions
           (namespace, dir_ino, dir_path, base_epoch, dir_seq, snapshot_seq,
            dir_version, updated_at_ms)
         VALUES (?1, ?2, '/', ?3, 1, 0, ?4, ?5)",
        params![
            namespace,
            ROOT_INO.as_slice(),
            epoch,
            version.as_slice(),
            now,
        ],
    )?;
    Ok(())
}
