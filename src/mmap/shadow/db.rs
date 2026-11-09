//! Local shadow metadata, layered on the foundation mm database.
//!
//! The main tree uses the foundation tables: `mm_dirs` for directories,
//! `mm_files` for live direct entries, `mm_versions` for immutable content
//! metadata and `mm_base` for the last server snapshot. The shadow adds four
//! tables that the foundation deliberately does not model:
//!
//! * `shadow_meta` — monotone kernel-inode allocator and client identity.
//! * `shadow_dirs` — checkout freshness, dirty/uploaded generations, handles.
//! * `shadow_versions` — per-version dirty state, open references and the
//!   local content hash. It is intentionally independent of `mm_files`, so an
//!   unlink does not erase the metadata an open descriptor still needs.
//! * `shadow_fuse` — `(ino, version) -> fuse_ino`, plus kernel lookup counts.
//!
//! One [`MmDb`] writer is guarded by a mutex; reads use independent `ReadTx`
//! snapshots. Long network work never holds the mutex.

use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

use rusqlite::{Connection, OptionalExtension, Row, params};

use crate::mmap::db::MmTx;
use crate::mmap::types::{
    BatchId, BatchRecord, DirAttrs, DirRecord, EntryKind, FileRecord, Hash, Ino, LockId,
    ManifestEntry, MmBase, MmRole, MmSeq, Phase, VersionRecord,
};
use crate::mmap::{MmDb, MmError, now_ms};

use super::ShadowError;
use super::layout::ShadowLayout;

const SHADOW_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS shadow_meta (
  id                 INTEGER PRIMARY KEY CHECK (id = 0),
  fuse_ino_next      INTEGER NOT NULL CHECK (fuse_ino_next >= 2),
  client_id          BLOB NOT NULL CHECK (length(client_id) = 16),
  revalidate_ttl_ms  INTEGER NOT NULL CHECK (revalidate_ttl_ms >= 0),
  created_at_ms      INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS shadow_dirs (
  dir_ino            BLOB PRIMARY KEY NOT NULL CHECK (length(dir_ino) = 16),
  valid_until_ms     INTEGER NOT NULL DEFAULT 0 CHECK (valid_until_ms >= 0),
  dirty_gen          INTEGER NOT NULL DEFAULT 0 CHECK (dirty_gen >= 0),
  uploaded_gen       INTEGER NOT NULL DEFAULT 0 CHECK (uploaded_gen >= 0),
  upload_state       TEXT NOT NULL DEFAULT 'idle' CHECK (
                       upload_state IN ('idle','dirty','snapshotting','locking','uploading','conflict','locked','failed')),
  batch_id           BLOB CHECK (batch_id IS NULL OR length(batch_id) = 16),
  lock_id            BLOB CHECK (lock_id IS NULL OR length(lock_id) = 16),
  dir_handles        INTEGER NOT NULL DEFAULT 0 CHECK (dir_handles >= 0),
  bodies_checked_out INTEGER NOT NULL DEFAULT 0 CHECK (bodies_checked_out IN (0,1)),
  local_only         INTEGER NOT NULL DEFAULT 0 CHECK (local_only IN (0,1)),
  snapshot_seq       INTEGER NOT NULL DEFAULT 0 CHECK (snapshot_seq >= 0),
  snapshot_gen       INTEGER NOT NULL DEFAULT 0 CHECK (snapshot_gen >= 0),
  last_checkout_ms   INTEGER NOT NULL DEFAULT 0 CHECK (last_checkout_ms >= 0)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS shadow_versions (
  ino               BLOB NOT NULL CHECK (length(ino) = 16),
  version           INTEGER NOT NULL CHECK (version >= 1),
  size              INTEGER NOT NULL CHECK (size >= 0),
  file_root         BLOB NOT NULL CHECK (length(file_root) = 32),
  content_hash      BLOB NOT NULL CHECK (length(content_hash) = 32),
  mtime_ns          INTEGER NOT NULL CHECK (mtime_ns >= 0),
  dirty_gen         INTEGER NOT NULL DEFAULT 0 CHECK (dirty_gen >= 0),
  synced_size       INTEGER NOT NULL DEFAULT 0 CHECK (synced_size >= 0),
  synced_mtime_ns   INTEGER NOT NULL DEFAULT 0 CHECK (synced_mtime_ns >= 0),
  open_refs         INTEGER NOT NULL DEFAULT 0 CHECK (open_refs >= 0),
  state             TEXT NOT NULL DEFAULT 'clean' CHECK (
                      state IN ('remote','clean','dirty','uploading','deleted')),
  PRIMARY KEY (ino, version)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS shadow_fuse (
  fuse_ino  INTEGER PRIMARY KEY CHECK (fuse_ino > 0),
  ino       BLOB NOT NULL CHECK (length(ino) = 16),
  version   INTEGER NOT NULL CHECK (version >= 0),
  kind      TEXT NOT NULL CHECK (kind IN ('file','symlink','dir')),
  nlookup   INTEGER NOT NULL DEFAULT 0 CHECK (nlookup >= 0),
  UNIQUE (ino, version)
) STRICT;

CREATE INDEX IF NOT EXISTS shadow_versions_state
  ON shadow_versions(state, dirty_gen);
"#;

/// One shadow directory plus its foundation row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowDir {
    pub record: DirRecord,
    pub valid_until_ms: i64,
    pub dirty_gen: u64,
    pub uploaded_gen: u64,
    pub upload_state: UploadPhase,
    pub batch_id: Option<BatchId>,
    pub lock_id: Option<LockId>,
    pub dir_handles: u64,
    pub bodies_checked_out: bool,
    pub local_only: bool,
    pub snapshot_seq: MmSeq,
    /// The dirty generation frozen by the upload that owns `batch_id`.
    pub snapshot_gen: u64,
    pub last_checkout_ms: i64,
}

impl ShadowDir {
    /// The current base triple.
    pub fn base(&self) -> MmBase {
        self.record.base
    }

    /// The canonical server path.
    pub fn path(&self) -> &str {
        &self.record.path
    }

    /// True when no local or remote change is waiting for upload.
    pub fn clean(&self) -> bool {
        self.uploaded_gen >= self.dirty_gen
    }
}

/// Local upload phase, distinct from the server's batch state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadPhase {
    Idle,
    Dirty,
    Snapshotting,
    Locking,
    Uploading,
    Conflict,
    Locked,
    Failed,
}

impl UploadPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Dirty => "dirty",
            Self::Snapshotting => "snapshotting",
            Self::Locking => "locking",
            Self::Uploading => "uploading",
            Self::Conflict => "conflict",
            Self::Locked => "locked",
            Self::Failed => "failed",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "idle" => Self::Idle,
            "dirty" => Self::Dirty,
            "snapshotting" => Self::Snapshotting,
            "locking" => Self::Locking,
            "uploading" => Self::Uploading,
            "conflict" => Self::Conflict,
            "locked" => Self::Locked,
            "failed" => Self::Failed,
            _ => return None,
        })
    }
}

/// Whether one local version has content on disk and whether that content is
/// still in sync with the last upload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionState {
    /// Metadata is known but the body has not been downloaded yet.
    Remote,
    /// Body exists and matches the last upload or checkout.
    Clean,
    /// Body or attributes were changed locally after the last upload.
    Dirty,
    /// A snapshot or upload is using this version.
    Uploading,
    /// The name was removed; an open descriptor may still hold the object.
    Deleted,
}

impl VersionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Remote => "remote",
            Self::Clean => "clean",
            Self::Dirty => "dirty",
            Self::Uploading => "uploading",
            Self::Deleted => "deleted",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "remote" => Self::Remote,
            "clean" => Self::Clean,
            "dirty" => Self::Dirty,
            "uploading" => Self::Uploading,
            "deleted" => Self::Deleted,
            _ => return None,
        })
    }
}

/// One local content version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowVersion {
    pub ino: Ino,
    pub version: u64,
    pub size: u64,
    pub file_root: Hash,
    pub content_hash: Hash,
    pub mtime_ns: i64,
    pub dirty_gen: u64,
    pub synced_size: u64,
    pub synced_mtime_ns: i64,
    pub open_refs: u64,
    pub state: VersionState,
}

/// One `shadow_fuse` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuseRow {
    pub fuse_ino: u64,
    pub ino: Ino,
    pub version: u64,
    pub kind: EntryKind,
    pub nlookup: u64,
}

/// One shadow metadata database.
pub struct ShadowDb {
    db: Mutex<MmDb>,
    namespace: String,
}

impl std::fmt::Debug for ShadowDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowDb")
            .field("namespace", &self.namespace)
            .field("db", &self.db)
            .finish()
    }
}

impl ShadowDb {
    /// Open (or create) the shadow database for one namespace.
    pub fn open(layout: &ShadowLayout, namespace: &str) -> Result<Self, ShadowError> {
        let mut db = MmDb::open(layout.db_path(), MmRole::Client, namespace)?;
        {
            let tx = db.write()?;
            tx.conn().execute_batch(SHADOW_DDL)?;
            migrate(tx.conn())?;
            seed(tx.conn())?;
            tx.commit()?;
        }
        Ok(Self {
            db: Mutex::new(db),
            namespace: namespace.to_owned(),
        })
    }

    /// The namespace this shadow serves.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The database file path.
    pub fn path(&self) -> PathBuf {
        self.db
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .path()
            .to_path_buf()
    }

    /// Run one read snapshot.
    pub fn read<T>(
        &self,
        f: impl FnOnce(&crate::mmap::ReadTx) -> Result<T, ShadowError>,
    ) -> Result<T, ShadowError> {
        let db = self.db.lock().unwrap_or_else(PoisonError::into_inner);
        let tx = db.read()?;
        f(&tx)
    }

    /// Run one write transaction.
    pub fn write<T>(
        &self,
        f: impl FnOnce(&crate::mmap::WriteTx<'_>) -> Result<T, ShadowError>,
    ) -> Result<T, ShadowError> {
        let mut db = self.db.lock().unwrap_or_else(PoisonError::into_inner);
        let tx = db.write()?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }

    /// The global sequence and epoch.
    pub fn epoch_and_seq(&self) -> Result<(u64, MmSeq), ShadowError> {
        self.read(|tx| Ok((tx.epoch()?, tx.mm_seq()?)))
    }

    /// The stable client id used by upload requests.
    pub fn client_id(&self) -> Result<[u8; 16], ShadowError> {
        self.read(|tx| {
            let bytes: Vec<u8> = tx.conn().query_row(
                "SELECT client_id FROM shadow_meta WHERE id = 0",
                [],
                |row| row.get(0),
            )?;
            bytes
                .try_into()
                .map_err(|_| ShadowError::Invalid("client id is not 16 bytes"))
        })
    }

    /// The configured revalidation TTL in milliseconds.
    pub fn revalidate_ttl_ms(&self) -> Result<u64, ShadowError> {
        self.read(|tx| {
            let value: i64 = tx.conn().query_row(
                "SELECT revalidate_ttl_ms FROM shadow_meta WHERE id = 0",
                [],
                |row| row.get(0),
            )?;
            u64::try_from(value).map_err(|_| ShadowError::Invalid("negative TTL"))
        })
    }

    /// Set the revalidation TTL.
    pub fn set_revalidate_ttl_ms(&self, ttl_ms: u64) -> Result<(), ShadowError> {
        self.write(|tx| {
            tx.conn().execute(
                "UPDATE shadow_meta SET revalidate_ttl_ms = ?1 WHERE id = 0",
                params![to_i64(ttl_ms)?],
            )?;
            Ok(())
        })
    }

    /// One directory with its shadow state.
    pub fn shadow_dir(&self, ino: Ino) -> Result<Option<ShadowDir>, ShadowError> {
        self.read(|tx| shadow_dir_tx(tx, ino))
    }

    /// One directory by canonical path.
    pub fn shadow_dir_by_path(&self, path: &str) -> Result<Option<ShadowDir>, ShadowError> {
        self.read(|tx| {
            let record = tx.dir_by_path(path)?;
            match record {
                Some(record) => shadow_dir_from_record(tx, record),
                None => Ok(None),
            }
        })
    }

    /// Every known directory, ordered by path.
    pub fn shadow_dirs(&self) -> Result<Vec<ShadowDir>, ShadowError> {
        self.read(|tx| {
            let mut out = Vec::new();
            for record in tx.dirs()? {
                if let Some(dir) = shadow_dir_from_record(tx, record)? {
                    out.push(dir);
                }
            }
            Ok(out)
        })
    }

    /// One live direct entry by inode, including deleted tombstones.
    pub fn file(&self, ino: Ino) -> Result<Option<FileRecord>, ShadowError> {
        self.read(|tx| Ok(tx.file(ino)?))
    }

    /// One live direct entry by parent and name.
    pub fn file_by_name(
        &self,
        dir_ino: Ino,
        name: &str,
    ) -> Result<Option<FileRecord>, ShadowError> {
        self.read(|tx| Ok(tx.file_by_name(dir_ino, name)?))
    }

    /// Every live direct entry of one directory, ordered by name.
    pub fn files(&self, dir_ino: Ino) -> Result<Vec<FileRecord>, ShadowError> {
        self.read(|tx| {
            Ok(tx
                .files(dir_ino)?
                .into_iter()
                .filter(|f| !f.deleted)
                .collect())
        })
    }

    /// Every direct entry, including deleted tombstones.
    pub fn files_with_deleted(&self, dir_ino: Ino) -> Result<Vec<FileRecord>, ShadowError> {
        self.read(|tx| Ok(tx.files(dir_ino)?))
    }

    /// One content version from the foundation table.
    pub fn version(&self, ino: Ino, version: u64) -> Result<Option<VersionRecord>, ShadowError> {
        self.read(|tx| Ok(tx.version(ino, version)?))
    }

    /// The stored base manifest of one directory.
    pub fn base_manifest(&self, dir_ino: Ino) -> Result<Vec<ManifestEntry>, ShadowError> {
        self.read(|tx| Ok(tx.base_manifest(dir_ino)?))
    }

    /// Insert or replace one directory row.
    pub fn put_dir(&self, dir: &DirRecord) -> Result<(), ShadowError> {
        self.write(|tx| {
            tx.put_dir(dir)?;
            Ok(())
        })
    }

    /// Delete one directory row and its foundation children.
    pub fn delete_dir(&self, ino: Ino) -> Result<bool, ShadowError> {
        self.write(|tx| {
            tx.conn().execute(
                "DELETE FROM shadow_dirs WHERE dir_ino = ?1",
                params![ino.as_slice()],
            )?;
            Ok(tx.delete_dir(ino)?)
        })
    }

    /// Insert or replace one direct entry.
    pub fn put_file(&self, file: &FileRecord) -> Result<(), ShadowError> {
        self.write(|tx| {
            tx.put_file(file)?;
            Ok(())
        })
    }

    /// Insert or replace one immutable content version.
    pub fn put_version(&self, version: &VersionRecord) -> Result<(), ShadowError> {
        self.write(|tx| {
            tx.put_version(version)?;
            Ok(())
        })
    }

    /// Replace the directory base triple.
    pub fn set_base(&self, ino: Ino, base: &MmBase) -> Result<(), ShadowError> {
        self.write(|tx| {
            tx.set_base(ino, base)?;
            Ok(())
        })
    }

    /// Replace the stored base manifest.
    pub fn replace_base_manifest(
        &self,
        dir_ino: Ino,
        entries: &[ManifestEntry],
    ) -> Result<(), ShadowError> {
        self.write(|tx| {
            tx.conn().execute(
                "DELETE FROM mm_base WHERE namespace = ?1 AND dir_ino = ?2",
                params![self.namespace, dir_ino.as_slice()],
            )?;
            for entry in entries {
                if entry.op.is_delete() {
                    continue;
                }
                tx.conn().execute(
                    "INSERT INTO mm_base
                       (namespace, dir_ino, name, ino, kind, mode, uid, gid, mtime_ns,
                        size, file_root, content_hash, target)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                    params![
                        self.namespace,
                        dir_ino.as_slice(),
                        entry.name,
                        entry.ino.as_slice(),
                        entry.kind.as_str(),
                        i64::from(entry.mode),
                        i64::from(entry.uid),
                        i64::from(entry.gid),
                        entry.mtime_ns,
                        to_i64(entry.size)?,
                        entry.file_root.as_slice(),
                        entry.content_hash.as_ref().map(|h| h.as_slice()),
                        entry.target.as_deref(),
                    ],
                )?;
            }
            Ok(())
        })
    }

    /// Record one committed batch.
    pub fn put_batch(&self, batch: &BatchRecord) -> Result<bool, ShadowError> {
        self.write(|tx| Ok(tx.put_batch(batch)?))
    }

    /// Reset transient state left by an earlier process.
    ///
    /// The kernel drops every lookup reference on unmount, so the persisted
    /// counts are stale. An interrupted checkout is retried from a stale base;
    /// an interrupted upload keeps its dirty generations.
    pub fn reset_after_crash(&self) -> Result<(), ShadowError> {
        self.write(|tx| {
            tx.conn().execute(
                "UPDATE shadow_dirs
                 SET upload_state = CASE
                       WHEN upload_state IN ('snapshotting','locking','uploading')
                         THEN 'dirty'
                       ELSE upload_state END,
                     dir_handles = 0",
                [],
            )?;
            tx.conn().execute(
                "UPDATE mm_dirs SET phase = 'stale', updated_at_ms = ?1
                 WHERE namespace = ?2 AND phase = 'checking_out'",
                params![now_ms(), self.namespace],
            )?;
            tx.conn().execute(
                "UPDATE shadow_fuse
                 SET nlookup = CASE WHEN fuse_ino = 1 THEN 1 ELSE 0 END",
                [],
            )?;
            Ok(())
        })
    }

    /// True when one local version row exists.
    pub fn has_version_row(&self, ino: Ino, version: u64) -> Result<bool, ShadowError> {
        self.read(|tx| {
            let exists: i64 = tx.conn().query_row(
                "SELECT EXISTS(SELECT 1 FROM shadow_versions WHERE ino = ?1 AND version = ?2)",
                params![ino.as_slice(), to_i64(version)?],
                |row| row.get(0),
            )?;
            Ok(exists != 0)
        })
    }

    /// True when an inode id is already used by a live or tombstoned entry or
    /// by a directory.
    pub fn ino_exists(&self, ino: Ino) -> Result<bool, ShadowError> {
        self.read(|tx| {
            let exists: i64 = tx.conn().query_row(
                "SELECT
                   EXISTS(SELECT 1 FROM mm_files WHERE namespace = ?1 AND ino = ?2)
                OR EXISTS(SELECT 1 FROM mm_dirs WHERE namespace = ?1 AND ino = ?2)
                OR EXISTS(SELECT 1 FROM shadow_versions WHERE ino = ?2)",
                params![self.namespace, ino.as_slice()],
                |row| row.get(0),
            )?;
            Ok(exists != 0)
        })
    }

    /// The current `shadow_dirs` row.
    pub fn shadow_dir_row(&self, ino: Ino) -> Result<Option<ShadowDir>, ShadowError> {
        self.shadow_dir(ino)
    }

    /// Insert or replace one shadow directory row.
    pub fn put_shadow_dir(&self, dir: &ShadowDir) -> Result<(), ShadowError> {
        self.write(|tx| put_shadow_dir_tx(tx.conn(), &self.namespace, dir))
    }

    /// Increment a directory's dirty generation and return the new value.
    pub fn bump_dir_dirty(&self, ino: Ino) -> Result<u64, ShadowError> {
        self.write(|tx| bump_dir_dirty_tx(tx.conn(), &self.namespace, ino))
    }

    /// Update the upload phase of one directory.
    pub fn set_upload_phase(
        &self,
        ino: Ino,
        phase: UploadPhase,
        batch_id: Option<BatchId>,
        lock_id: Option<LockId>,
    ) -> Result<(), ShadowError> {
        self.write(|tx| {
            tx.conn().execute(
                "UPDATE shadow_dirs
                 SET upload_state = ?1, batch_id = ?2, lock_id = ?3
                 WHERE dir_ino = ?4",
                params![
                    phase.as_str(),
                    batch_id.as_ref().map(|id| id.as_bytes().as_slice()),
                    lock_id.as_ref().map(|id| id.as_bytes().as_slice()),
                    ino.as_slice(),
                ],
            )?;
            Ok(())
        })
    }

    /// Mark checkout freshness.
    #[allow(clippy::too_many_arguments)]
    pub fn set_checkout_state(
        &self,
        ino: Ino,
        base: &MmBase,
        snapshot_seq: MmSeq,
        attrs: &DirAttrs,
        phase: Phase,
        bodies: bool,
        valid_until_ms: i64,
    ) -> Result<(), ShadowError> {
        self.write(|tx| {
            tx.conn().execute(
                "UPDATE mm_dirs
                 SET base_epoch = ?1, base_seq = ?2, dir_version = ?3,
                     phase = ?4, mode = ?5, uid = ?6, gid = ?7, mtime_ns = ?8,
                     deleted = 0, updated_at_ms = ?9
                 WHERE namespace = ?10 AND ino = ?11",
                params![
                    to_i64(base.epoch)?,
                    to_i64(base.dir_seq.get())?,
                    base.dir_version.as_slice(),
                    phase.as_str(),
                    i64::from(attrs.mode),
                    i64::from(attrs.uid),
                    i64::from(attrs.gid),
                    attrs.mtime_ns,
                    now_ms(),
                    self.namespace,
                    ino.as_slice(),
                ],
            )?;
            tx.conn().execute(
                "INSERT INTO shadow_dirs
                   (dir_ino, valid_until_ms, dirty_gen, uploaded_gen, upload_state,
                    batch_id, lock_id, dir_handles, bodies_checked_out, local_only,
                    snapshot_seq, last_checkout_ms)
                 VALUES (?1, ?2, 0, 0, 'idle', NULL, NULL, 0, ?3, 0, ?4, ?5)
                 ON CONFLICT(dir_ino) DO UPDATE SET
                   valid_until_ms = excluded.valid_until_ms,
                   bodies_checked_out = MAX(shadow_dirs.bodies_checked_out, excluded.bodies_checked_out),
                   snapshot_seq = excluded.snapshot_seq,
                   last_checkout_ms = excluded.last_checkout_ms",
                params![
                    ino.as_slice(),
                    valid_until_ms,
                    i64::from(bodies),
                    to_i64(snapshot_seq.get())?,
                    now_ms(),
                ],
            )?;
            tx.conn().execute(
                "INSERT INTO mm_dir_versions
                   (namespace, dir_ino, dir_path, base_epoch, dir_seq, snapshot_seq,
                    dir_version, updated_at_ms)
                 SELECT ?1, ?2, path, ?3, ?4, ?5, ?6, ?7 FROM mm_dirs
                 WHERE namespace = ?1 AND ino = ?2
                 ON CONFLICT(namespace, dir_ino) DO UPDATE SET
                   dir_path = excluded.dir_path,
                   base_epoch = excluded.base_epoch,
                   dir_seq = excluded.dir_seq,
                   snapshot_seq = excluded.snapshot_seq,
                   dir_version = excluded.dir_version,
                   updated_at_ms = excluded.updated_at_ms",
                params![
                    self.namespace,
                    ino.as_slice(),
                    to_i64(base.epoch)?,
                    to_i64(base.dir_seq.get())?,
                    to_i64(snapshot_seq.get())?,
                    base.dir_version.as_slice(),
                    now_ms(),
                ],
            )?;
            Ok(())
        })
    }

    /// Set the local-only flag for a directory created without a server round
    /// trip.
    pub fn set_local_only(&self, ino: Ino, local_only: bool) -> Result<(), ShadowError> {
        self.write(|tx| {
            tx.conn().execute(
                "UPDATE shadow_dirs SET local_only = ?1 WHERE dir_ino = ?2",
                params![i64::from(local_only), ino.as_slice()],
            )?;
            Ok(())
        })
    }

    /// Adjust a directory's open-handle count and return the new count.
    pub fn add_dir_handle(&self, ino: Ino, delta: i64) -> Result<u64, ShadowError> {
        self.write(|tx| {
            tx.conn().execute(
                "UPDATE shadow_dirs
                 SET dir_handles = MAX(0, dir_handles + ?1)
                 WHERE dir_ino = ?2",
                params![delta, ino.as_slice()],
            )?;
            let handles: i64 = tx
                .conn()
                .query_row(
                    "SELECT dir_handles FROM shadow_dirs WHERE dir_ino = ?1",
                    params![ino.as_slice()],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or(0);
            u64::try_from(handles).map_err(|_| ShadowError::Invalid("negative dir handles"))
        })
    }

    /// Record one content or metadata mutation on a live file.
    ///
    /// The directory generation, the entry attributes and the local version
    /// move in one transaction, so a crash never leaves a size without a
    /// dirty generation or a dirty generation without a size.
    pub fn record_mutation(
        &self,
        dir_ino: Ino,
        file: &FileRecord,
        size: u64,
        mtime_ns: i64,
        file_root: Hash,
        content_hash: Hash,
    ) -> Result<u64, ShadowError> {
        self.write(|tx| {
            let generation = bump_dir_dirty_tx(tx.conn(), &self.namespace, dir_ino)?;
            tx.put_file(file)?;
            let changed = tx.conn().execute(
                "UPDATE shadow_versions
                 SET size = ?1, mtime_ns = ?2, dirty_gen = ?3, state = 'dirty',
                     file_root = ?4, content_hash = ?5
                 WHERE ino = ?6 AND version = ?7",
                params![
                    to_i64(size)?,
                    mtime_ns,
                    to_i64(generation)?,
                    file_root.as_slice(),
                    content_hash.as_slice(),
                    file.ino.as_slice(),
                    to_i64(file.version)?,
                ],
            )?;
            if changed == 0 {
                return Err(ShadowError::NotFound);
            }
            Ok(generation)
        })
    }

    /// Record a metadata-only mutation (mode, owner, mtime) on a directory or
    /// file version.
    pub fn record_metadata(
        &self,
        dir_ino: Ino,
        file: &FileRecord,
        mtime_ns: i64,
    ) -> Result<u64, ShadowError> {
        self.write(|tx| {
            let generation = bump_dir_dirty_tx(tx.conn(), &self.namespace, dir_ino)?;
            tx.put_file(file)?;
            let changed = tx.conn().execute(
                "UPDATE shadow_versions
                 SET mtime_ns = ?1, dirty_gen = ?2, state = 'dirty'
                 WHERE ino = ?3 AND version = ?4",
                params![
                    mtime_ns,
                    to_i64(generation)?,
                    file.ino.as_slice(),
                    to_i64(file.version)?,
                ],
            )?;
            if changed == 0 {
                let content_hash = file.content_hash.unwrap_or_else(|| {
                    *blake3::hash(file.target.as_deref().unwrap_or_default()).as_bytes()
                });
                put_shadow_version_tx(
                    tx.conn(),
                    &ShadowVersion {
                        ino: file.ino,
                        version: file.version,
                        size: file.size,
                        file_root: file.file_root,
                        content_hash,
                        mtime_ns,
                        dirty_gen: generation,
                        synced_size: file.size,
                        synced_mtime_ns: mtime_ns,
                        open_refs: 0,
                        state: VersionState::Dirty,
                    },
                )?;
            }
            Ok(generation)
        })
    }

    /// One local version.
    pub fn shadow_version(
        &self,
        ino: Ino,
        version: u64,
    ) -> Result<Option<ShadowVersion>, ShadowError> {
        self.read(|tx| shadow_version_tx(tx.conn(), ino, version))
    }

    /// Insert or replace one local version.
    pub fn put_shadow_version(&self, version: &ShadowVersion) -> Result<(), ShadowError> {
        self.write(|tx| put_shadow_version_tx(tx.conn(), version))
    }

    /// Mark one version dirty at one directory generation.
    pub fn touch_version_dirty(
        &self,
        ino: Ino,
        version: u64,
        dirty_gen: u64,
        size: u64,
        mtime_ns: i64,
    ) -> Result<(), ShadowError> {
        self.write(|tx| {
            let changed = tx.conn().execute(
                "UPDATE shadow_versions
                 SET dirty_gen = ?1, state = 'dirty', size = ?2, mtime_ns = ?3
                 WHERE ino = ?4 AND version = ?5",
                params![
                    to_i64(dirty_gen)?,
                    to_i64(size)?,
                    mtime_ns,
                    ino.as_slice(),
                    to_i64(version)?,
                ],
            )?;
            if changed == 0 {
                return Err(ShadowError::NotFound);
            }
            Ok(())
        })
    }

    /// Store the hashes computed from a frozen snapshot.
    pub fn set_version_snapshot(
        &self,
        ino: Ino,
        version: u64,
        size: u64,
        file_root: Hash,
        content_hash: Hash,
        mtime_ns: i64,
    ) -> Result<(), ShadowError> {
        self.write(|tx| {
            tx.conn().execute(
                "UPDATE shadow_versions
                 SET size = ?1, file_root = ?2, content_hash = ?3, mtime_ns = ?4
                 WHERE ino = ?5 AND version = ?6",
                params![
                    to_i64(size)?,
                    file_root.as_slice(),
                    content_hash.as_slice(),
                    mtime_ns,
                    ino.as_slice(),
                    to_i64(version)?,
                ],
            )?;
            Ok(())
        })
    }

    /// Mark a downloaded object as present and clean.
    pub fn mark_version_clean(&self, ino: Ino, version: u64) -> Result<(), ShadowError> {
        self.write(|tx| {
            tx.conn().execute(
                "UPDATE shadow_versions
                 SET state = 'clean', synced_size = size, synced_mtime_ns = mtime_ns
                 WHERE ino = ?1 AND version = ?2 AND dirty_gen = 0",
                params![ino.as_slice(), to_i64(version)?],
            )?;
            Ok(())
        })
    }

    /// Remember the dirty generation frozen by the current upload.
    ///
    /// The generation is durable before `BEGIN`, so a committed batch whose
    /// local acknowledgement was lost can clear exactly the dirty versions it
    /// contained and leave a later write dirty.
    pub fn set_snapshot_gen(&self, dir_ino: Ino, generation: u64) -> Result<(), ShadowError> {
        self.write(|tx| {
            tx.conn().execute(
                "UPDATE shadow_dirs SET snapshot_gen = ?1 WHERE dir_ino = ?2",
                params![to_i64(generation)?, dir_ino.as_slice()],
            )?;
            Ok(())
        })
    }

    /// Forget one batch id and keep the dirty generations for the next fsync.
    pub fn clear_batch(&self, dir_ino: Ino, phase: UploadPhase) -> Result<(), ShadowError> {
        self.write(|tx| {
            tx.conn().execute(
                "UPDATE shadow_dirs
                 SET upload_state = ?1, batch_id = NULL, lock_id = NULL,
                     snapshot_gen = 0
                 WHERE dir_ino = ?2",
                params![phase.as_str(), dir_ino.as_slice()],
            )?;
            Ok(())
        })
    }

    /// Adopt one committed batch.
    ///
    /// The new base and manifest replace the old ones, dirty generations at
    /// or below `snapshot_gen` become clean, and the upload bookkeeping
    /// resets. `batch` is absent when the result came from `GET batch/{id}`,
    /// which carries no entry count or byte total. Returns `false` when a
    /// checkout already recorded the same or a newer snapshot; the batch is
    /// then dropped without touching the newer base.
    pub fn publish_committed(
        &self,
        dir_ino: Ino,
        base: MmBase,
        snapshot_seq: MmSeq,
        snapshot_gen: u64,
        valid_until_ms: i64,
        batch: Option<&BatchRecord>,
    ) -> Result<bool, ShadowError> {
        self.write(|tx| {
            // A checkout may have run between the caller's read and this
            // transaction. Re-check inside the write lock so a commit can
            // never roll the directory back.
            let current_seq: i64 = tx.conn().query_row(
                "SELECT snapshot_seq FROM shadow_dirs WHERE dir_ino = ?1",
                params![dir_ino.as_slice()],
                |row| row.get(0),
            )?;
            let current_seq = u64::try_from(current_seq)
                .map_err(|_| ShadowError::Invalid("negative snapshot sequence"))?;
            if current_seq >= snapshot_seq.get() {
                tx.conn().execute(
                    "UPDATE shadow_dirs
                     SET upload_state = CASE
                           WHEN uploaded_gen >= dirty_gen THEN 'idle' ELSE 'dirty' END,
                         batch_id = NULL, lock_id = NULL, snapshot_gen = 0
                     WHERE dir_ino = ?1",
                    params![dir_ino.as_slice()],
                )?;
                return Ok(false);
            }
            let path: String = tx.conn().query_row(
                "SELECT path FROM mm_dirs WHERE namespace = ?1 AND ino = ?2",
                params![self.namespace, dir_ino.as_slice()],
                |row| row.get(0),
            )?;
            tx.conn().execute(
                "UPDATE mm_dirs
                 SET base_epoch = ?1, base_seq = ?2, dir_version = ?3,
                     phase = 'ready', updated_at_ms = ?4
                 WHERE namespace = ?5 AND ino = ?6",
                params![
                    to_i64(base.epoch)?,
                    to_i64(base.dir_seq.get())?,
                    base.dir_version.as_slice(),
                    now_ms(),
                    self.namespace,
                    dir_ino.as_slice(),
                ],
            )?;
            tx.conn().execute(
                "INSERT INTO mm_dir_versions
                   (namespace, dir_ino, dir_path, base_epoch, dir_seq, snapshot_seq,
                    dir_version, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(namespace, dir_ino) DO UPDATE SET
                   dir_path = excluded.dir_path,
                   base_epoch = excluded.base_epoch,
                   dir_seq = excluded.dir_seq,
                   snapshot_seq = excluded.snapshot_seq,
                   dir_version = excluded.dir_version,
                   updated_at_ms = excluded.updated_at_ms",
                params![
                    self.namespace,
                    dir_ino.as_slice(),
                    path,
                    to_i64(base.epoch)?,
                    to_i64(base.dir_seq.get())?,
                    to_i64(snapshot_seq.get())?,
                    base.dir_version.as_slice(),
                    now_ms(),
                ],
            )?;
            tx.conn().execute(
                "DELETE FROM mm_base WHERE namespace = ?1 AND dir_ino = ?2",
                params![self.namespace, dir_ino.as_slice()],
            )?;
            tx.conn().execute(
                "INSERT INTO mm_base
                   (namespace, dir_ino, name, ino, kind, mode, uid, gid, mtime_ns,
                    size, file_root, content_hash, target)
                 SELECT namespace, dir_ino, name, ino, kind, mode, uid, gid, mtime_ns,
                        size, file_root, NULL, target
                 FROM mm_files
                 WHERE namespace = ?1 AND dir_ino = ?2 AND deleted = 0",
                params![self.namespace, dir_ino.as_slice()],
            )?;
            tx.conn().execute(
                "UPDATE shadow_versions
                 SET dirty_gen = 0,
                     state = CASE WHEN state = 'dirty' THEN 'clean' ELSE state END,
                     synced_size = size,
                     synced_mtime_ns = mtime_ns
                 WHERE ino IN (
                   SELECT ino FROM mm_files
                   WHERE namespace = ?1 AND dir_ino = ?2 AND deleted = 0
                 ) AND dirty_gen > 0 AND dirty_gen <= ?3",
                params![self.namespace, dir_ino.as_slice(), to_i64(snapshot_gen)?,],
            )?;
            tx.conn().execute(
                "UPDATE shadow_dirs
                 SET uploaded_gen = MAX(uploaded_gen, ?1),
                     upload_state = 'idle', batch_id = NULL, lock_id = NULL,
                     snapshot_gen = 0,
                     snapshot_seq = MAX(snapshot_seq, ?2),
                     valid_until_ms = ?3
                 WHERE dir_ino = ?4",
                params![
                    to_i64(snapshot_gen)?,
                    to_i64(snapshot_seq.get())?,
                    valid_until_ms,
                    dir_ino.as_slice(),
                ],
            )?;
            tx.conn().execute(
                "UPDATE shadow_dirs
                 SET local_only = 0, valid_until_ms = 0, bodies_checked_out = 0
                 WHERE dir_ino IN (
                   SELECT ino FROM mm_files
                   WHERE namespace = ?1 AND dir_ino = ?2
                     AND kind = 'dir' AND deleted = 0
                 )",
                params![self.namespace, dir_ino.as_slice()],
            )?;
            tx.conn().execute(
                "UPDATE mm_dirs SET phase = 'stale'
                 WHERE namespace = ?1 AND ino IN (
                   SELECT ino FROM mm_files
                   WHERE namespace = ?1 AND dir_ino = ?2
                     AND kind = 'dir' AND deleted = 0
                 )",
                params![self.namespace, dir_ino.as_slice()],
            )?;
            if let Some(batch) = batch {
                tx.put_batch(batch)?;
            }
            Ok(true)
        })
    }

    /// Add or remove one open reference.
    pub fn add_open_ref(&self, ino: Ino, version: u64, delta: i64) -> Result<u64, ShadowError> {
        self.write(|tx| {
            tx.conn().execute(
                "UPDATE shadow_versions
                 SET open_refs = MAX(0, open_refs + ?1)
                 WHERE ino = ?2 AND version = ?3",
                params![delta, ino.as_slice(), to_i64(version)?],
            )?;
            let refs: i64 = tx.conn().query_row(
                "SELECT open_refs FROM shadow_versions WHERE ino = ?1 AND version = ?2",
                params![ino.as_slice(), to_i64(version)?],
                |row| row.get(0),
            )?;
            u64::try_from(refs).map_err(|_| ShadowError::Invalid("negative open refs"))
        })
    }

    /// Look up one `(ino, version)` mapping.
    pub fn fuse_for(&self, ino: Ino, version: u64, kind: EntryKind) -> Result<u64, ShadowError> {
        self.write(|tx| allocate_fuse(tx.conn(), ino, version, kind))
    }

    /// One `shadow_fuse` row.
    pub fn fuse_row(&self, fuse_ino: u64) -> Result<Option<FuseRow>, ShadowError> {
        self.read(|tx| fuse_row_tx(tx.conn(), fuse_ino))
    }

    /// Add kernel lookup references.
    pub fn bump_nlookup(&self, fuse_ino: u64, delta: i64) -> Result<(), ShadowError> {
        self.write(|tx| {
            tx.conn().execute(
                "UPDATE shadow_fuse SET nlookup = MAX(0, nlookup + ?1) WHERE fuse_ino = ?2",
                params![delta, to_i64_from_i64(fuse_ino)?],
            )?;
            Ok(())
        })
    }

    /// Versions that are safe to collect after their last reference dropped.
    ///
    /// A version is collectable when it is not the current version of a live
    /// entry, has no open references, no kernel lookup references, and is not
    /// dirty. The caller removes object files and mapping rows.
    pub fn collectable_versions(&self) -> Result<Vec<(Ino, u64, u64)>, ShadowError> {
        self.read(|tx| {
            let mut stmt = tx.conn().prepare(
                "SELECT v.ino, v.version, f.fuse_ino
                 FROM shadow_versions v
                 JOIN shadow_fuse f ON f.ino = v.ino AND f.version = v.version
                 WHERE v.open_refs = 0
                   AND v.dirty_gen = 0
                   AND f.nlookup = 0
                   AND NOT EXISTS (
                     SELECT 1 FROM mm_files m
                     WHERE m.namespace = ?1 AND m.ino = v.ino
                       AND m.version = v.version AND m.deleted = 0)
                 ORDER BY v.ino, v.version",
            )?;
            let rows = stmt.query_map(params![self.namespace], |row| {
                Ok((blob16(row, 0)?, row_u64(row, 1)?, row_u64(row, 2)?))
            })?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        })
    }

    /// Delete one version row and one fuse mapping, if it is still
    /// unreferenced and non-current.
    pub fn drop_version(&self, ino: Ino, version: u64, fuse_ino: u64) -> Result<bool, ShadowError> {
        self.write(|tx| {
            let current: Option<i64> = tx
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM mm_files
                     WHERE namespace = ?1 AND ino = ?2 AND version = ?3 AND deleted = 0",
                    params![self.namespace, ino.as_slice(), to_i64(version)?],
                    |row| row.get(0),
                )
                .optional()?;
            if current.unwrap_or(0) != 0 {
                return Ok(false);
            }
            tx.conn().execute(
                "DELETE FROM shadow_versions WHERE ino = ?1 AND version = ?2",
                params![ino.as_slice(), to_i64(version)?],
            )?;
            tx.conn().execute(
                "DELETE FROM mm_versions WHERE namespace = ?1 AND ino = ?2 AND version = ?3",
                params![self.namespace, ino.as_slice(), to_i64(version)?],
            )?;
            tx.conn().execute(
                "DELETE FROM shadow_fuse WHERE fuse_ino = ?1 AND ino = ?2 AND version = ?3",
                params![to_i64_from_i64(fuse_ino)?, ino.as_slice(), to_i64(version)?],
            )?;
            Ok(true)
        })
    }

    /// Current `(ino, version)` for a live entry.
    pub fn current_version(&self, ino: Ino) -> Result<Option<u64>, ShadowError> {
        self.read(|tx| {
            Ok(tx
                .file(ino)?
                .filter(|file| !file.deleted)
                .map(|file| file.version))
        })
    }

    /// Every directly-named child directory inode.
    pub fn child_dir_inos(&self, dir_ino: Ino) -> Result<Vec<Ino>, ShadowError> {
        self.read(|tx| {
            Ok(tx
                .files(dir_ino)?
                .into_iter()
                .filter(|file| !file.deleted && file.kind.is_dir())
                .map(|file| file.ino)
                .collect())
        })
    }
}

/// Add shadow columns introduced after the first schema.
pub(super) fn migrate(conn: &Connection) -> Result<(), ShadowError> {
    let mut columns = conn.prepare("PRAGMA table_info(shadow_dirs)")?;
    let names = columns.query_map([], |row| row.get::<_, String>(1))?;
    let mut has_snapshot_gen = false;
    for name in names {
        if name? == "snapshot_gen" {
            has_snapshot_gen = true;
        }
    }
    if !has_snapshot_gen {
        conn.execute(
            "ALTER TABLE shadow_dirs
             ADD COLUMN snapshot_gen INTEGER NOT NULL DEFAULT 0
             CHECK (snapshot_gen >= 0)",
            [],
        )?;
    }
    Ok(())
}

fn seed(conn: &Connection) -> Result<(), ShadowError> {
    conn.execute(
        "INSERT INTO shadow_meta
           (id, fuse_ino_next, client_id, revalidate_ttl_ms, created_at_ms)
         VALUES (0, 2, randomblob(16), 1000, ?1)
         ON CONFLICT(id) DO NOTHING",
        params![now_ms()],
    )?;
    conn.execute(
        "INSERT INTO shadow_dirs
           (dir_ino, valid_until_ms, dirty_gen, uploaded_gen, upload_state,
            batch_id, lock_id, dir_handles, bodies_checked_out, local_only,
            snapshot_seq, last_checkout_ms)
         VALUES (zeroblob(16), 0, 0, 0, 'idle', NULL, NULL, 0, 0, 0, 0, 0)
         ON CONFLICT(dir_ino) DO NOTHING",
        [],
    )?;
    conn.execute(
        "INSERT INTO shadow_fuse (fuse_ino, ino, version, kind, nlookup)
         VALUES (1, zeroblob(16), 0, 'dir', 1)
         ON CONFLICT(fuse_ino) DO NOTHING",
        [],
    )?;
    Ok(())
}

fn shadow_dir_tx<T: MmTx>(tx: &T, ino: Ino) -> Result<Option<ShadowDir>, ShadowError> {
    let record = match tx.dir(ino)? {
        Some(record) => record,
        None => return Ok(None),
    };
    shadow_dir_from_record(tx, record)
}

fn shadow_dir_from_record<T: MmTx>(
    tx: &T,
    record: DirRecord,
) -> Result<Option<ShadowDir>, ShadowError> {
    let row = tx
        .conn()
        .query_row(
            "SELECT valid_until_ms, dirty_gen, uploaded_gen, upload_state, batch_id,
                    lock_id, dir_handles, bodies_checked_out, local_only, snapshot_seq,
                    snapshot_gen, last_checkout_ms
             FROM shadow_dirs WHERE dir_ino = ?1",
            params![record.ino.as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                ))
            },
        )
        .optional()?;
    let Some((
        valid_until_ms,
        dirty_gen,
        uploaded_gen,
        upload_state,
        batch_id,
        lock_id,
        dir_handles,
        bodies,
        local_only,
        snapshot_seq,
        snapshot_gen,
        last_checkout_ms,
    )) = row
    else {
        return Ok(None);
    };
    Ok(Some(ShadowDir {
        record,
        valid_until_ms,
        dirty_gen: u64::try_from(dirty_gen).map_err(|_| ShadowError::Invalid("negative gen"))?,
        uploaded_gen: u64::try_from(uploaded_gen)
            .map_err(|_| ShadowError::Invalid("negative gen"))?,
        upload_state: UploadPhase::parse(&upload_state)
            .ok_or(ShadowError::Invalid("unknown upload state"))?,
        batch_id: batch_id.map(batch_id_from_bytes).transpose()?,
        lock_id: lock_id.map(lock_id_from_bytes).transpose()?,
        dir_handles: u64::try_from(dir_handles)
            .map_err(|_| ShadowError::Invalid("negative handles"))?,
        bodies_checked_out: bodies != 0,
        local_only: local_only != 0,
        snapshot_seq: MmSeq::new(
            u64::try_from(snapshot_seq).map_err(|_| ShadowError::Invalid("negative seq"))?,
        ),
        snapshot_gen: u64::try_from(snapshot_gen)
            .map_err(|_| ShadowError::Invalid("negative generation"))?,
        last_checkout_ms,
    }))
}

pub(super) fn put_shadow_dir_tx(
    conn: &Connection,
    namespace: &str,
    dir: &ShadowDir,
) -> Result<(), ShadowError> {
    conn.execute(
        "INSERT INTO shadow_dirs
           (dir_ino, valid_until_ms, dirty_gen, uploaded_gen, upload_state, batch_id,
            lock_id, dir_handles, bodies_checked_out, local_only, snapshot_seq,
            snapshot_gen, last_checkout_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
         ON CONFLICT(dir_ino) DO UPDATE SET
           valid_until_ms = excluded.valid_until_ms,
           dirty_gen = excluded.dirty_gen,
           uploaded_gen = excluded.uploaded_gen,
           upload_state = excluded.upload_state,
           batch_id = excluded.batch_id,
           lock_id = excluded.lock_id,
           dir_handles = excluded.dir_handles,
           bodies_checked_out = excluded.bodies_checked_out,
           local_only = excluded.local_only,
           snapshot_seq = excluded.snapshot_seq,
           snapshot_gen = excluded.snapshot_gen,
           last_checkout_ms = excluded.last_checkout_ms",
        params![
            dir.record.ino.as_slice(),
            dir.valid_until_ms,
            to_i64(dir.dirty_gen)?,
            to_i64(dir.uploaded_gen)?,
            dir.upload_state.as_str(),
            dir.batch_id.as_ref().map(|id| id.as_bytes().as_slice()),
            dir.lock_id.as_ref().map(|id| id.as_bytes().as_slice()),
            to_i64(dir.dir_handles)?,
            i64::from(dir.bodies_checked_out),
            i64::from(dir.local_only),
            to_i64(dir.snapshot_seq.get())?,
            to_i64(dir.snapshot_gen)?,
            dir.last_checkout_ms,
        ],
    )?;
    let _ = namespace;
    Ok(())
}

pub(super) fn bump_dir_dirty_tx(
    conn: &Connection,
    namespace: &str,
    ino: Ino,
) -> Result<u64, ShadowError> {
    conn.execute(
        "INSERT INTO shadow_dirs (dir_ino, upload_state)
         VALUES (?1, 'dirty') ON CONFLICT(dir_ino) DO NOTHING",
        params![ino.as_slice()],
    )?;
    let value: i64 = conn.query_row(
        "UPDATE shadow_dirs SET dirty_gen = dirty_gen + 1, upload_state = 'dirty'
         WHERE dir_ino = ?1 RETURNING dirty_gen",
        params![ino.as_slice()],
        |row| row.get(0),
    )?;
    conn.execute(
        "UPDATE mm_dirs SET updated_at_ms = ?1 WHERE namespace = ?2 AND ino = ?3",
        params![now_ms(), namespace, ino.as_slice()],
    )?;
    u64::try_from(value).map_err(|_| ShadowError::Invalid("negative dirty generation"))
}

fn shadow_version_tx(
    conn: &Connection,
    ino: Ino,
    version: u64,
) -> Result<Option<ShadowVersion>, ShadowError> {
    let row = conn
        .query_row(
            "SELECT size, file_root, content_hash, mtime_ns, dirty_gen,
                    synced_size, synced_mtime_ns, open_refs, state
             FROM shadow_versions WHERE ino = ?1 AND version = ?2",
            params![ino.as_slice(), to_i64(version)?],
            |row| {
                Ok((
                    row_u64(row, 0)?,
                    blob32(row, 1)?,
                    blob32(row, 2)?,
                    row.get::<_, i64>(3)?,
                    row_u64(row, 4)?,
                    row_u64(row, 5)?,
                    row.get::<_, i64>(6)?,
                    row_u64(row, 7)?,
                    row.get::<_, String>(8)?,
                ))
            },
        )
        .optional()?;
    let Some((
        size,
        file_root,
        content_hash,
        mtime_ns,
        dirty_gen,
        synced_size,
        synced_mtime_ns,
        open_refs,
        state,
    )) = row
    else {
        return Ok(None);
    };
    Ok(Some(ShadowVersion {
        ino,
        version,
        size,
        file_root,
        content_hash,
        mtime_ns,
        dirty_gen,
        synced_size,
        synced_mtime_ns,
        open_refs,
        state: VersionState::parse(&state).ok_or(ShadowError::Invalid("unknown version state"))?,
    }))
}

pub(super) fn put_shadow_version_tx(
    conn: &Connection,
    version: &ShadowVersion,
) -> Result<(), ShadowError> {
    conn.execute(
        "INSERT INTO shadow_versions
           (ino, version, size, file_root, content_hash, mtime_ns, dirty_gen,
            synced_size, synced_mtime_ns, open_refs, state)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(ino, version) DO UPDATE SET
           size = excluded.size,
           file_root = excluded.file_root,
           content_hash = excluded.content_hash,
           mtime_ns = excluded.mtime_ns,
           dirty_gen = excluded.dirty_gen,
           synced_size = excluded.synced_size,
           synced_mtime_ns = excluded.synced_mtime_ns,
           open_refs = excluded.open_refs,
           state = excluded.state",
        params![
            version.ino.as_slice(),
            to_i64(version.version)?,
            to_i64(version.size)?,
            version.file_root.as_slice(),
            version.content_hash.as_slice(),
            version.mtime_ns,
            to_i64(version.dirty_gen)?,
            to_i64(version.synced_size)?,
            version.synced_mtime_ns,
            to_i64(version.open_refs)?,
            version.state.as_str(),
        ],
    )?;
    Ok(())
}

fn fuse_row_tx(conn: &Connection, fuse_ino: u64) -> Result<Option<FuseRow>, ShadowError> {
    let row = conn
        .query_row(
            "SELECT ino, version, kind, nlookup FROM shadow_fuse WHERE fuse_ino = ?1",
            params![to_i64_from_i64(fuse_ino)?],
            |row| {
                Ok((
                    blob16(row, 0)?,
                    row_u64(row, 1)?,
                    row.get::<_, String>(2)?,
                    row_u64(row, 3)?,
                ))
            },
        )
        .optional()?;
    let Some((ino, version, kind, nlookup)) = row else {
        return Ok(None);
    };
    Ok(Some(FuseRow {
        fuse_ino,
        ino,
        version,
        kind: EntryKind::parse(&kind).ok_or(ShadowError::Invalid("unknown entry kind"))?,
        nlookup,
    }))
}

pub(super) fn allocate_fuse(
    conn: &Connection,
    ino: Ino,
    version: u64,
    kind: EntryKind,
) -> Result<u64, ShadowError> {
    if let Some(existing) = conn
        .query_row(
            "SELECT fuse_ino FROM shadow_fuse WHERE ino = ?1 AND version = ?2",
            params![ino.as_slice(), to_i64(version)?],
            |row| row_u64(row, 0),
        )
        .optional()?
    {
        return Ok(existing);
    }
    let fuse_ino: i64 = conn.query_row(
        "UPDATE shadow_meta SET fuse_ino_next = fuse_ino_next + 1
         WHERE id = 0 RETURNING fuse_ino_next - 1",
        [],
        |row| row.get(0),
    )?;
    let fuse_ino = u64::try_from(fuse_ino).map_err(|_| ShadowError::Invalid("negative inode"))?;
    conn.execute(
        "INSERT INTO shadow_fuse (fuse_ino, ino, version, kind, nlookup)
         VALUES (?1, ?2, ?3, ?4, 0)",
        params![
            to_i64_from_i64(fuse_ino)?,
            ino.as_slice(),
            to_i64(version)?,
            kind.as_str()
        ],
    )?;
    Ok(fuse_ino)
}

fn batch_id_from_bytes(bytes: Vec<u8>) -> Result<BatchId, ShadowError> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| ShadowError::Invalid("batch id is not 16 bytes"))?;
    Ok(BatchId::from_bytes(bytes))
}

fn lock_id_from_bytes(bytes: Vec<u8>) -> Result<LockId, ShadowError> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| ShadowError::Invalid("lock id is not 16 bytes"))?;
    Ok(LockId::from_bytes(bytes))
}

fn blob16(row: &Row<'_>, index: usize) -> rusqlite::Result<Ino> {
    let value: Vec<u8> = row.get(index)?;
    value.try_into().map_err(|_| {
        rusqlite::Error::InvalidColumnType(index, "blob16".into(), rusqlite::types::Type::Blob)
    })
}

fn blob32(row: &Row<'_>, index: usize) -> rusqlite::Result<Hash> {
    let value: Vec<u8> = row.get(index)?;
    value.try_into().map_err(|_| {
        rusqlite::Error::InvalidColumnType(index, "blob32".into(), rusqlite::types::Type::Blob)
    })
}

fn row_u64(row: &Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| {
        rusqlite::Error::InvalidColumnType(index, "u64".into(), rusqlite::types::Type::Integer)
    })
}

fn to_i64(value: u64) -> Result<i64, ShadowError> {
    i64::try_from(value).map_err(|_| ShadowError::Invalid("integer does not fit i64"))
}

fn to_i64_from_i64(value: u64) -> Result<i64, ShadowError> {
    i64::try_from(value).map_err(|_| ShadowError::Invalid("inode does not fit i64"))
}

impl From<rusqlite::Error> for ShadowError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Db(MmError::Sqlite(error))
    }
}
