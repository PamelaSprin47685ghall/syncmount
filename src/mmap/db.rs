//! mm database handle, transactions and typed CRUD.
//!
//! # Concurrency
//!
//! One [`MmDb`] owns exactly one writer connection. [`MmDb::write`] takes
//! `&mut self` and opens `BEGIN IMMEDIATE`, so Rust makes a second concurrent
//! writer through the same handle unrepresentable. [`MmDb::read`] opens a
//! separate connection and starts `BEGIN DEFERRED`, so a checkout snapshot
//! never blocks a commit and never sees a partial batch.
//!
//! # Identity
//!
//! The mm namespace has no hard links: one inode has exactly one name. The
//! root directory is `ROOT_INO` and has no `mm_files` row. Child directories
//! do have a `mm_files` row under their parent, in addition to their own
//! `mm_dirs` row.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, params};

use super::manifest::Manifest;
use super::schema;
use super::types::{
    BatchId, BatchRecord, CHUNK_BYTES, DirAttrs, DirRecord, DirSeq, DirVersionRecord, EntryKind,
    EntryOp, FileRecord, Hash, Ino, LockId, LockRecord, ManifestEntry, MmBase, MmRole, MmSeq,
    Phase, UploadRecord, UploadState, VersionRecord, validate_dir_path, validate_name,
    validate_namespace,
};
use super::{MmError, now_ms};
use crate::store::sqlite::ChunkRef;

/// Result alias used across the mm database boundary.
pub type Result<T, E = MmError> = std::result::Result<T, E>;

const DIR_COLUMNS: &str = "ino, path, base_epoch, base_seq, dir_version, phase, mode, uid, gid, mtime_ns, deleted, \
     created_at_ms, updated_at_ms";

const FILE_COLUMNS: &str = "ino, dir_ino, name, kind, mode, uid, gid, mtime_ns, size, file_root, content_hash, target, \
     version, deleted, created_at_ms, updated_at_ms";

const VERSION_COLUMNS: &str =
    "ino, version, size, file_root, content_hash, chunk_count, created_at_ms";

const UPLOAD_COLUMNS: &str = "batch_id, lock_id, dir_path, dir_ino, base_epoch, base_seq, dir_version, manifest_hash, \
     state, spool_path, bytes_received, created_at_ms, updated_at_ms, expires_at_ms";

const LOCK_COLUMNS: &str = "lock_id, dir_path, dir_ino, owner_client, owner_session, base_epoch, base_seq, batch_id, \
     expires_at_ms, created_at_ms, renewed_at_ms, progress_bytes";

const BATCH_COLUMNS: &str = "batch_id, dir_path, dir_ino, base_epoch, base_seq, base_seq_after, snapshot_seq, \
     dir_version_before, dir_version_after, manifest_hash, client_id, entry_count, bytes, \
     committed_at_ms";

const DIR_VERSION_COLUMNS: &str =
    "dir_ino, dir_path, base_epoch, dir_seq, snapshot_seq, dir_version, updated_at_ms";

/// One mm database file.
pub struct MmDb {
    conn: Connection,
    role: MmRole,
    namespace: String,
    path: PathBuf,
}

impl std::fmt::Debug for MmDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmDb")
            .field("role", &self.role)
            .field("namespace", &self.namespace)
            .field("path", &self.path)
            .finish()
    }
}

impl MmDb {
    /// Open (or create) the mm database for one namespace.
    ///
    /// The parent directory is created when missing. The file is then
    /// canonicalized so later read connections resolve the same path after a
    /// `chdir` in the daemon. A file path is required: [`Self::read`] opens a
    /// second connection by path, so `:memory:` cannot serve read snapshots.
    pub fn open(
        path: impl AsRef<Path>,
        role: MmRole,
        namespace: impl Into<String>,
    ) -> Result<Self> {
        let namespace = namespace.into();
        validate_namespace(&namespace)?;
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut conn = Connection::open(&path)?;
        let path = std::fs::canonicalize(&path).unwrap_or(path);
        schema::configure(&conn, role)?;
        schema::migrate(&mut conn, role, &namespace)?;
        Ok(Self {
            conn,
            role,
            namespace,
            path,
        })
    }

    /// The role this database was created for.
    pub fn role(&self) -> MmRole {
        self.role
    }

    /// The namespace this database serves.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The database file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The migration cursor stored in `PRAGMA user_version`.
    pub fn schema_version(&self) -> Result<i64> {
        self.read()?.schema_version()
    }

    /// Open an independent read snapshot.
    pub fn read(&self) -> Result<ReadTx> {
        let conn = open_reader(&self.path)?;
        conn.execute_batch("BEGIN DEFERRED")?;
        Ok(ReadTx {
            conn,
            namespace: self.namespace.clone(),
        })
    }

    /// Open the single write transaction.
    pub fn write(&mut self) -> Result<WriteTx<'_>> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        Ok(WriteTx {
            conn: &self.conn,
            namespace: &self.namespace,
            finished: false,
        })
    }

    /// Read the current epoch through a fresh snapshot.
    pub fn epoch(&self) -> Result<u64> {
        self.read()?.epoch()
    }

    /// Read the current global sequence through a fresh snapshot.
    pub fn mm_seq(&self) -> Result<MmSeq> {
        self.read()?.mm_seq()
    }
}

/// A read-only snapshot on its own connection.
pub struct ReadTx {
    conn: Connection,
    namespace: String,
}

impl std::fmt::Debug for ReadTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadTx")
            .field("namespace", &self.namespace)
            .finish()
    }
}

impl Drop for ReadTx {
    fn drop(&mut self) {
        // Closing the connection ends the transaction; the explicit rollback
        // keeps the intent obvious and is harmless when it already ended.
        let _ = self.conn.execute_batch("ROLLBACK");
    }
}

impl MmTx for ReadTx {
    fn conn(&self) -> &Connection {
        &self.conn
    }

    fn namespace(&self) -> &str {
        &self.namespace
    }
}

/// The single write transaction.
pub struct WriteTx<'a> {
    conn: &'a Connection,
    namespace: &'a str,
    finished: bool,
}

impl std::fmt::Debug for WriteTx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteTx")
            .field("namespace", &self.namespace)
            .finish()
    }
}

impl Drop for WriteTx<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.conn.execute_batch("ROLLBACK");
        }
    }
}

impl MmTx for WriteTx<'_> {
    fn conn(&self) -> &Connection {
        self.conn
    }

    fn namespace(&self) -> &str {
        self.namespace
    }
}

impl WriteTx<'_> {
    /// Commit the transaction. A failed commit leaves the caller with a
    /// rolled-back transaction, never a half-applied batch.
    pub fn commit(mut self) -> Result<()> {
        self.conn.execute_batch("COMMIT")?;
        self.finished = true;
        Ok(())
    }

    /// Roll the transaction back now instead of on drop.
    pub fn rollback(mut self) {
        let _ = self.conn.execute_batch("ROLLBACK");
        self.finished = true;
    }

    /// Advance the global mm sequence and return the new value.
    pub fn next_mm_seq(&self) -> Result<MmSeq> {
        let value: i64 = self.conn.query_row(
            "UPDATE mm_meta SET mm_seq = mm_seq + 1, updated_at_ms = ?1
             WHERE id = 0 RETURNING mm_seq",
            params![now_ms()],
            |row| row.get(0),
        )?;
        Ok(MmSeq::new(
            u64::try_from(value).map_err(|_| MmError::Corrupt("negative mm_seq"))?,
        ))
    }

    /// Replace the mm epoch. Only a database reset/rebuild does this.
    pub fn set_epoch(&self, epoch: u64) -> Result<()> {
        if epoch == 0 {
            return Err(MmError::Invalid("epoch must be at least 1"));
        }
        self.conn.execute(
            "UPDATE mm_meta SET epoch = ?1, updated_at_ms = ?2 WHERE id = 0",
            params![to_i64(epoch)?, now_ms()],
        )?;
        Ok(())
    }

    /// Insert or replace one directory and its authoritative version row.
    ///
    /// The version row's `snapshot_seq` is the current global sequence on
    /// insert and is left untouched on update; a batch that creates a
    /// directory should call [`Self::next_mm_seq`] first. This method does not
    /// write the parent's `mm_files` entry; the caller adds that separate
    /// `EntryKind::Dir` row with [`Self::put_file`].
    pub fn put_dir(&self, dir: &DirRecord) -> Result<()> {
        validate_dir_path(&dir.path)?;
        validate_epoch(dir.base.epoch)?;
        let now = now_ms();
        self.conn.execute(
            "INSERT INTO mm_dirs
               (namespace, ino, path, base_epoch, base_seq, dir_version, phase,
                mode, uid, gid, mtime_ns, deleted, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
             ON CONFLICT(namespace, ino) DO UPDATE SET
               path = excluded.path,
               base_epoch = excluded.base_epoch,
               base_seq = excluded.base_seq,
               dir_version = excluded.dir_version,
               phase = excluded.phase,
               mode = excluded.mode,
               uid = excluded.uid,
               gid = excluded.gid,
               mtime_ns = excluded.mtime_ns,
               deleted = excluded.deleted,
               updated_at_ms = excluded.updated_at_ms",
            params![
                self.namespace(),
                dir.ino.as_slice(),
                dir.path,
                to_i64(dir.base.epoch)?,
                to_i64(dir.base.dir_seq.get())?,
                dir.base.dir_version.as_slice(),
                dir.phase.as_str(),
                i64::from(dir.attrs.mode),
                i64::from(dir.attrs.uid),
                i64::from(dir.attrs.gid),
                dir.attrs.mtime_ns,
                i64::from(dir.deleted),
                dir.created_at_ms,
                dir.updated_at_ms,
            ],
        )?;
        let snapshot = self.mm_seq()?;
        self.conn.execute(
            "INSERT INTO mm_dir_versions
               (namespace, dir_ino, dir_path, base_epoch, dir_seq, snapshot_seq,
                dir_version, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(namespace, dir_ino) DO UPDATE SET
               dir_path = excluded.dir_path,
               base_epoch = excluded.base_epoch,
               dir_seq = excluded.dir_seq,
               dir_version = excluded.dir_version,
               updated_at_ms = excluded.updated_at_ms",
            params![
                self.namespace(),
                dir.ino.as_slice(),
                dir.path,
                to_i64(dir.base.epoch)?,
                to_i64(dir.base.dir_seq.get())?,
                to_i64(snapshot.get())?,
                dir.base.dir_version.as_slice(),
                now,
            ],
        )?;
        Ok(())
    }

    /// Delete one directory. Child rows cascade.
    ///
    /// The `mm_files` row that represents this directory inside its parent is
    /// not a child of this row; the caller removes that entry separately.
    pub fn delete_dir(&self, ino: Ino) -> Result<bool> {
        let changed = self.conn.execute(
            "DELETE FROM mm_dirs WHERE namespace = ?1 AND ino = ?2",
            params![self.namespace(), ino.as_slice()],
        )?;
        Ok(changed != 0)
    }

    /// Replace the base triple of one directory in both mirror tables.
    pub fn set_base(&self, ino: Ino, base: &MmBase) -> Result<()> {
        validate_epoch(base.epoch)?;
        let now = now_ms();
        let changed = self.conn.execute(
            "UPDATE mm_dirs
             SET base_epoch = ?1, base_seq = ?2, dir_version = ?3, updated_at_ms = ?4
             WHERE namespace = ?5 AND ino = ?6",
            params![
                to_i64(base.epoch)?,
                to_i64(base.dir_seq.get())?,
                base.dir_version.as_slice(),
                now,
                self.namespace(),
                ino.as_slice(),
            ],
        )?;
        if changed == 0 {
            return Err(MmError::NotFound);
        }
        let changed = self.conn.execute(
            "UPDATE mm_dir_versions
             SET base_epoch = ?1, dir_seq = ?2, dir_version = ?3, updated_at_ms = ?4
             WHERE namespace = ?5 AND dir_ino = ?6",
            params![
                to_i64(base.epoch)?,
                to_i64(base.dir_seq.get())?,
                base.dir_version.as_slice(),
                now,
                self.namespace(),
                ino.as_slice(),
            ],
        )?;
        if changed == 0 {
            return Err(MmError::NotFound);
        }
        Ok(())
    }

    /// Advance one directory's `dir_seq` and return the new value.
    pub fn bump_dir(&self, ino: Ino) -> Result<DirSeq> {
        let now = now_ms();
        let value: Option<i64> = self
            .conn
            .query_row(
                "UPDATE mm_dir_versions
                 SET dir_seq = dir_seq + 1, updated_at_ms = ?1
                 WHERE namespace = ?2 AND dir_ino = ?3 RETURNING dir_seq",
                params![now, self.namespace(), ino.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let value = value.ok_or(MmError::NotFound)?;
        self.conn.execute(
            "UPDATE mm_dirs SET base_seq = ?1, updated_at_ms = ?2
             WHERE namespace = ?3 AND ino = ?4",
            params![value, now, self.namespace(), ino.as_slice()],
        )?;
        Ok(DirSeq::new(
            u64::try_from(value).map_err(|_| MmError::Corrupt("negative dir_seq"))?,
        ))
    }

    /// Record the snapshot sequence covered by one directory version.
    pub fn set_dir_snapshot(&self, ino: Ino, seq: MmSeq) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE mm_dir_versions SET snapshot_seq = ?1, updated_at_ms = ?2
             WHERE namespace = ?3 AND dir_ino = ?4",
            params![
                to_i64(seq.get())?,
                now_ms(),
                self.namespace(),
                ino.as_slice()
            ],
        )?;
        if changed == 0 {
            return Err(MmError::NotFound);
        }
        Ok(())
    }

    /// Insert or replace one direct entry.
    ///
    /// A name has exactly one inode, so a row with the same `(dir_ino, name)`
    /// but a different inode is removed first. Versions cascade.
    pub fn put_file(&self, file: &FileRecord) -> Result<()> {
        validate_name(&file.name)?;
        self.conn.execute(
            "DELETE FROM mm_files
             WHERE namespace = ?1 AND dir_ino = ?2 AND name = ?3 AND ino <> ?4",
            params![
                self.namespace(),
                file.dir_ino.as_slice(),
                file.name,
                file.ino.as_slice(),
            ],
        )?;
        self.conn.execute(
            "INSERT INTO mm_files
               (namespace, ino, dir_ino, name, kind, mode, uid, gid, mtime_ns, size,
                file_root, content_hash, target, version, deleted, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
             ON CONFLICT(namespace, ino) DO UPDATE SET
               dir_ino = excluded.dir_ino,
               name = excluded.name,
               kind = excluded.kind,
               mode = excluded.mode,
               uid = excluded.uid,
               gid = excluded.gid,
               mtime_ns = excluded.mtime_ns,
               size = excluded.size,
               file_root = excluded.file_root,
               content_hash = excluded.content_hash,
               target = excluded.target,
               version = excluded.version,
               deleted = excluded.deleted,
               updated_at_ms = excluded.updated_at_ms",
            params![
                self.namespace(),
                file.ino.as_slice(),
                file.dir_ino.as_slice(),
                file.name,
                file.kind.as_str(),
                i64::from(file.attrs.mode),
                i64::from(file.attrs.uid),
                i64::from(file.attrs.gid),
                file.attrs.mtime_ns,
                to_i64(file.size)?,
                file.file_root.as_slice(),
                file.content_hash.as_ref().map(|hash| hash.as_slice()),
                file.target.as_deref(),
                to_i64(file.version)?,
                i64::from(file.deleted),
                file.created_at_ms,
                file.updated_at_ms,
            ],
        )?;
        Ok(())
    }

    /// Delete one direct entry. Versions cascade.
    pub fn delete_file(&self, ino: Ino) -> Result<bool> {
        let changed = self.conn.execute(
            "DELETE FROM mm_files WHERE namespace = ?1 AND ino = ?2",
            params![self.namespace(), ino.as_slice()],
        )?;
        Ok(changed != 0)
    }

    /// Insert or replace one immutable content version.
    pub fn put_version(&self, version: &VersionRecord) -> Result<()> {
        self.conn.execute(
            "INSERT INTO mm_versions
               (namespace, ino, version, size, file_root, content_hash, chunk_count, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(namespace, ino, version) DO UPDATE SET
               size = excluded.size,
               file_root = excluded.file_root,
               content_hash = excluded.content_hash,
               chunk_count = excluded.chunk_count",
            params![
                self.namespace(),
                version.ino.as_slice(),
                to_i64(version.version)?,
                to_i64(version.size)?,
                version.file_root.as_slice(),
                version.content_hash.as_slice(),
                i64::from(version.chunk_count),
                version.created_at_ms,
            ],
        )?;
        Ok(())
    }

    /// Insert one content-addressed chunk.
    ///
    /// The caller must have already hashed the bytes; this method re-checks
    /// both the hash and the 64 KiB bound so a corrupt caller cannot poison
    /// the base content used by rsync.
    pub fn put_chunk(&self, hash: Hash, data: &[u8]) -> Result<()> {
        if data.is_empty() || data.len() > CHUNK_BYTES as usize {
            return Err(MmError::Invalid("chunk length is outside 1..=65536"));
        }
        if blake3::hash(data).as_bytes() != &hash {
            return Err(MmError::Invalid("chunk hash does not match its bytes"));
        }
        self.conn.execute(
            "INSERT INTO mm_chunks (hash, len, data, refcount)
             VALUES (?1, ?2, ?3, 0) ON CONFLICT(hash) DO NOTHING",
            params![hash.as_slice(), data.len() as i64, data],
        )?;
        Ok(())
    }

    /// Replace the ordered chunk list of one version and maintain refcounts.
    ///
    /// The chunks themselves must already be present in `mm_chunks`; the
    /// foreign key enforces that.
    pub fn put_version_chunks(&self, ino: Ino, version: u64, chunks: &[ChunkRef]) -> Result<()> {
        let old: Vec<Hash> = {
            let mut stmt = self.conn.prepare(
                "SELECT chunk_hash FROM mm_version_chunks
                 WHERE namespace = ?1 AND ino = ?2 AND version = ?3",
            )?;
            let rows = stmt.query_map(
                params![self.namespace(), ino.as_slice(), to_i64(version)?],
                |row| blob32(row, 0),
            )?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        self.conn.execute(
            "DELETE FROM mm_version_chunks
             WHERE namespace = ?1 AND ino = ?2 AND version = ?3",
            params![self.namespace(), ino.as_slice(), to_i64(version)?],
        )?;
        for (index, chunk) in chunks.iter().enumerate() {
            if chunk.chunk_no as usize != index {
                return Err(MmError::Invalid("chunk numbers are not contiguous"));
            }
            if chunk.offset != u64::from(chunk.chunk_no) * u64::from(CHUNK_BYTES) {
                return Err(MmError::Invalid("chunk offset does not match its number"));
            }
            if chunk.len == 0 || chunk.len > CHUNK_BYTES {
                return Err(MmError::Invalid("chunk length is outside 1..=65536"));
            }
            self.conn.execute(
                "INSERT INTO mm_version_chunks
                   (namespace, ino, version, chunk_no, chunk_hash, offset, len)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    self.namespace(),
                    ino.as_slice(),
                    to_i64(version)?,
                    i64::from(chunk.chunk_no),
                    chunk.hash.as_slice(),
                    to_i64(chunk.offset)?,
                    i64::from(chunk.len),
                ],
            )?;
            self.conn.execute(
                "UPDATE mm_chunks SET refcount = refcount + 1 WHERE hash = ?1",
                params![chunk.hash.as_slice()],
            )?;
        }
        // Every old reference was deleted above; decrement all of them.
        // New references were inserted and incremented in the loop. A hash
        // present in both old and new therefore nets to zero, while a removed
        // hash drops by one and a new hash rises by one.
        for hash in old {
            self.conn.execute(
                "UPDATE mm_chunks
                 SET refcount = CASE WHEN refcount > 0 THEN refcount - 1 ELSE 0 END
                 WHERE hash = ?1",
                params![hash.as_slice()],
            )?;
        }
        Ok(())
    }

    /// Delete every chunk with no remaining version reference.
    pub fn gc_chunks(&self) -> Result<u64> {
        let deleted = self
            .conn
            .execute("DELETE FROM mm_chunks WHERE refcount = 0", [])?;
        Ok(deleted as u64)
    }

    /// Replace the stored base snapshot of one directory.
    ///
    /// Removing entries are not stored: the base describes what exists after
    /// the commit, not how it got there.
    pub fn replace_base_manifest(&self, dir_ino: Ino, manifest: &Manifest) -> Result<()> {
        self.conn.execute(
            "DELETE FROM mm_base WHERE namespace = ?1 AND dir_ino = ?2",
            params![self.namespace(), dir_ino.as_slice()],
        )?;
        for entry in manifest.entries() {
            if entry.op.is_delete() {
                continue;
            }
            self.conn.execute(
                "INSERT INTO mm_base
                   (namespace, dir_ino, name, ino, kind, mode, uid, gid, mtime_ns, size,
                    file_root, content_hash, target)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    self.namespace(),
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
                    entry.content_hash.as_ref().map(|hash| hash.as_slice()),
                    entry.target.as_deref(),
                ],
            )?;
        }
        Ok(())
    }

    /// Remove the stored base snapshot of one directory.
    pub fn clear_base(&self, dir_ino: Ino) -> Result<()> {
        self.conn.execute(
            "DELETE FROM mm_base WHERE namespace = ?1 AND dir_ino = ?2",
            params![self.namespace(), dir_ino.as_slice()],
        )?;
        Ok(())
    }

    /// Insert or replace one upload session.
    pub fn put_upload(&self, upload: &UploadRecord) -> Result<()> {
        validate_dir_path(&upload.dir_path)?;
        validate_epoch(upload.base_epoch)?;
        self.conn.execute(
            "INSERT INTO mm_uploads
               (namespace, batch_id, lock_id, dir_path, dir_ino, base_epoch, base_seq,
                dir_version, manifest_hash, state, spool_path, bytes_received,
                created_at_ms, updated_at_ms, expires_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT(namespace, batch_id) DO UPDATE SET
               lock_id = excluded.lock_id,
               dir_path = excluded.dir_path,
               dir_ino = excluded.dir_ino,
               base_epoch = excluded.base_epoch,
               base_seq = excluded.base_seq,
               dir_version = excluded.dir_version,
               manifest_hash = excluded.manifest_hash,
               state = excluded.state,
               spool_path = excluded.spool_path,
               bytes_received = excluded.bytes_received,
               updated_at_ms = excluded.updated_at_ms,
               expires_at_ms = excluded.expires_at_ms",
            params![
                self.namespace(),
                upload.batch_id.as_bytes().as_slice(),
                upload.lock_id.as_bytes().as_slice(),
                upload.dir_path,
                upload.dir_ino.as_slice(),
                to_i64(upload.base_epoch)?,
                to_i64(upload.base_seq.get())?,
                upload.dir_version.as_slice(),
                upload.manifest_hash.as_slice(),
                upload.state.as_str(),
                upload.spool_path,
                to_i64(upload.bytes_received)?,
                upload.created_at_ms,
                upload.updated_at_ms,
                upload.expires_at_ms,
            ],
        )?;
        Ok(())
    }

    /// Change the state of one upload session.
    pub fn set_upload_state(&self, batch_id: BatchId, state: UploadState) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE mm_uploads SET state = ?1, updated_at_ms = ?2
             WHERE namespace = ?3 AND batch_id = ?4",
            params![
                state.as_str(),
                now_ms(),
                self.namespace(),
                batch_id.as_bytes().as_slice(),
            ],
        )?;
        if changed == 0 {
            return Err(MmError::NotFound);
        }
        Ok(())
    }

    /// Record upload progress and extend the session deadline.
    pub fn update_upload_progress(
        &self,
        batch_id: BatchId,
        bytes_received: u64,
        expires_at_ms: i64,
    ) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE mm_uploads
             SET bytes_received = ?1, expires_at_ms = ?2, updated_at_ms = ?3
             WHERE namespace = ?4 AND batch_id = ?5",
            params![
                to_i64(bytes_received)?,
                expires_at_ms,
                now_ms(),
                self.namespace(),
                batch_id.as_bytes().as_slice(),
            ],
        )?;
        if changed == 0 {
            return Err(MmError::NotFound);
        }
        Ok(())
    }

    /// Delete one upload session.
    pub fn delete_upload(&self, batch_id: BatchId) -> Result<bool> {
        let changed = self.conn.execute(
            "DELETE FROM mm_uploads WHERE namespace = ?1 AND batch_id = ?2",
            params![self.namespace(), batch_id.as_bytes().as_slice()],
        )?;
        Ok(changed != 0)
    }

    /// Insert or replace one directory lock.
    ///
    /// The caller is responsible for the owner/TTL policy; this method only
    /// enforces the storage shape.
    pub fn put_lock(&self, lock: &LockRecord) -> Result<()> {
        validate_dir_path(&lock.dir_path)?;
        validate_epoch(lock.base_epoch)?;
        self.conn.execute(
            "INSERT INTO mm_locks
               (namespace, dir_path, dir_ino, lock_id, owner_client, owner_session,
                base_epoch, base_seq, batch_id, expires_at_ms, created_at_ms,
                renewed_at_ms, progress_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(namespace, dir_path) DO UPDATE SET
               dir_ino = excluded.dir_ino,
               lock_id = excluded.lock_id,
               owner_client = excluded.owner_client,
               owner_session = excluded.owner_session,
               base_epoch = excluded.base_epoch,
               base_seq = excluded.base_seq,
               batch_id = excluded.batch_id,
               expires_at_ms = excluded.expires_at_ms,
               renewed_at_ms = excluded.renewed_at_ms,
               progress_bytes = excluded.progress_bytes",
            params![
                self.namespace(),
                lock.dir_path,
                lock.dir_ino.as_slice(),
                lock.lock_id.as_bytes().as_slice(),
                lock.owner_client.as_slice(),
                lock.owner_session.as_slice(),
                to_i64(lock.base_epoch)?,
                to_i64(lock.base_seq.get())?,
                lock.batch_id.as_ref().map(|id| id.as_bytes().as_slice()),
                lock.expires_at_ms,
                lock.created_at_ms,
                lock.renewed_at_ms,
                to_i64(lock.progress_bytes)?,
            ],
        )?;
        Ok(())
    }

    /// Extend one lock and record progress.
    pub fn renew_lock(
        &self,
        lock_id: LockId,
        expires_at_ms: i64,
        progress_bytes: u64,
    ) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE mm_locks
             SET expires_at_ms = ?1, renewed_at_ms = ?2, progress_bytes = ?3
             WHERE namespace = ?4 AND lock_id = ?5",
            params![
                expires_at_ms,
                now_ms(),
                to_i64(progress_bytes)?,
                self.namespace(),
                lock_id.as_bytes().as_slice(),
            ],
        )?;
        Ok(changed != 0)
    }

    /// Delete one lock.
    pub fn delete_lock(&self, lock_id: LockId) -> Result<bool> {
        let changed = self.conn.execute(
            "DELETE FROM mm_locks WHERE namespace = ?1 AND lock_id = ?2",
            params![self.namespace(), lock_id.as_bytes().as_slice()],
        )?;
        Ok(changed != 0)
    }

    /// Delete every expired lock and return the ids that were removed.
    ///
    /// The caller aborts the uploads owned by those locks; the database
    /// method only removes the lease rows.
    pub fn delete_expired_locks(&self, now: i64) -> Result<Vec<LockId>> {
        let mut stmt = self.conn.prepare(
            "DELETE FROM mm_locks WHERE namespace = ?1 AND expires_at_ms < ?2
             RETURNING lock_id",
        )?;
        let rows = stmt.query_map(params![self.namespace(), now], |row| blob16(row, 0))?;
        let mut removed = Vec::new();
        for row in rows {
            removed.push(LockId::from_bytes(row?));
        }
        Ok(removed)
    }

    /// Append one immutable batch record.
    ///
    /// Returns true when the row was inserted and false when the same batch
    /// id already exists. A repeated begin/commit with the same manifest hash
    /// therefore sees the original row instead of writing a second one.
    pub fn put_batch(&self, batch: &BatchRecord) -> Result<bool> {
        validate_dir_path(&batch.dir_path)?;
        validate_epoch(batch.base_epoch)?;
        let inserted = self.conn.execute(
            "INSERT INTO mm_batches
               (namespace, batch_id, dir_path, dir_ino, base_epoch, base_seq,
                base_seq_after, snapshot_seq, dir_version_before, dir_version_after,
                manifest_hash, client_id, entry_count, bytes, committed_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT(namespace, batch_id) DO NOTHING",
            params![
                self.namespace(),
                batch.batch_id.as_bytes().as_slice(),
                batch.dir_path,
                batch.dir_ino.as_slice(),
                to_i64(batch.base_epoch)?,
                to_i64(batch.base_seq.get())?,
                to_i64(batch.base_seq_after.get())?,
                to_i64(batch.snapshot_seq.get())?,
                batch.dir_version_before.as_slice(),
                batch.dir_version_after.as_slice(),
                batch.manifest_hash.as_slice(),
                batch.client_id.as_slice(),
                i64::from(batch.entry_count),
                to_i64(batch.bytes)?,
                batch.committed_at_ms,
            ],
        )?;
        Ok(inserted != 0)
    }
}

/// Read methods shared by [`ReadTx`] and [`WriteTx`].
pub trait MmTx {
    /// The underlying connection.
    fn conn(&self) -> &Connection;

    /// The namespace served by this transaction.
    fn namespace(&self) -> &str;

    /// The migration cursor stored in `PRAGMA user_version`.
    fn schema_version(&self) -> Result<i64> {
        let version: i64 = self
            .conn()
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        Ok(version)
    }

    /// The current mm epoch.
    fn epoch(&self) -> Result<u64> {
        let value: i64 =
            self.conn()
                .query_row("SELECT epoch FROM mm_meta WHERE id = 0", [], |row| {
                    row.get(0)
                })?;
        u64::try_from(value).map_err(|_| MmError::Corrupt("negative epoch"))
    }

    /// The current global sequence.
    fn mm_seq(&self) -> Result<MmSeq> {
        let value: i64 =
            self.conn()
                .query_row("SELECT mm_seq FROM mm_meta WHERE id = 0", [], |row| {
                    row.get(0)
                })?;
        Ok(MmSeq::new(
            u64::try_from(value).map_err(|_| MmError::Corrupt("negative mm_seq"))?,
        ))
    }

    /// One directory row by inode.
    fn dir(&self, ino: Ino) -> Result<Option<DirRecord>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {DIR_COLUMNS} FROM mm_dirs WHERE namespace = ?1 AND ino = ?2"
        ))?;
        let row = stmt
            .query_row(params![self.namespace(), ino.as_slice()], dir_from_row)
            .optional()?;
        Ok(row)
    }

    /// One directory row by canonical path.
    fn dir_by_path(&self, path: &str) -> Result<Option<DirRecord>> {
        validate_dir_path(path)?;
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {DIR_COLUMNS} FROM mm_dirs WHERE namespace = ?1 AND path = ?2"
        ))?;
        let row = stmt
            .query_row(params![self.namespace(), path], dir_from_row)
            .optional()?;
        Ok(row)
    }

    /// Every directory row, ordered by path.
    fn dirs(&self) -> Result<Vec<DirRecord>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {DIR_COLUMNS} FROM mm_dirs WHERE namespace = ?1 ORDER BY path"
        ))?;
        let rows = stmt.query_map(params![self.namespace()], dir_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// The authoritative version row of one directory.
    fn dir_version_record(&self, ino: Ino) -> Result<Option<DirVersionRecord>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {DIR_VERSION_COLUMNS} FROM mm_dir_versions
             WHERE namespace = ?1 AND dir_ino = ?2"
        ))?;
        let row = stmt
            .query_row(
                params![self.namespace(), ino.as_slice()],
                dir_version_from_row,
            )
            .optional()?;
        Ok(row)
    }

    /// One directory's `dir_seq`.
    fn dir_seq(&self, ino: Ino) -> Result<Option<DirSeq>> {
        let value: Option<i64> = self
            .conn()
            .query_row(
                "SELECT dir_seq FROM mm_dir_versions WHERE namespace = ?1 AND dir_ino = ?2",
                params![self.namespace(), ino.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        value
            .map(|value| {
                u64::try_from(value)
                    .map(DirSeq::new)
                    .map_err(|_| MmError::Corrupt("negative dir_seq"))
            })
            .transpose()
    }

    /// One directory's canonical `dir_version`.
    fn dir_version(&self, ino: Ino) -> Result<Option<Hash>> {
        let value: Option<Vec<u8>> = self
            .conn()
            .query_row(
                "SELECT dir_version FROM mm_dir_versions WHERE namespace = ?1 AND dir_ino = ?2",
                params![self.namespace(), ino.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        value.map(blob32_value).transpose()
    }

    /// One directory's base triple.
    fn base(&self, ino: Ino) -> Result<Option<MmBase>> {
        let row = self
            .conn()
            .query_row(
                "SELECT base_epoch, dir_seq, dir_version FROM mm_dir_versions
                 WHERE namespace = ?1 AND dir_ino = ?2",
                params![self.namespace(), ino.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(epoch, dir_seq, dir_version)| {
            Ok(MmBase {
                epoch: u64::try_from(epoch).map_err(|_| MmError::Corrupt("negative epoch"))?,
                dir_seq: DirSeq::new(
                    u64::try_from(dir_seq).map_err(|_| MmError::Corrupt("negative dir_seq"))?,
                ),
                dir_version: blob32_value(dir_version)?,
            })
        })
        .transpose()
    }

    /// Every direct entry of one directory, ordered by name.
    fn files(&self, dir_ino: Ino) -> Result<Vec<FileRecord>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {FILE_COLUMNS} FROM mm_files
             WHERE namespace = ?1 AND dir_ino = ?2 ORDER BY name"
        ))?;
        let rows = stmt.query_map(params![self.namespace(), dir_ino.as_slice()], file_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// One direct entry by inode.
    fn file(&self, ino: Ino) -> Result<Option<FileRecord>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {FILE_COLUMNS} FROM mm_files WHERE namespace = ?1 AND ino = ?2"
        ))?;
        let row = stmt
            .query_row(params![self.namespace(), ino.as_slice()], file_from_row)
            .optional()?;
        Ok(row)
    }

    /// One direct entry by parent and name.
    fn file_by_name(&self, dir_ino: Ino, name: &str) -> Result<Option<FileRecord>> {
        validate_name(name)?;
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {FILE_COLUMNS} FROM mm_files
             WHERE namespace = ?1 AND dir_ino = ?2 AND name = ?3"
        ))?;
        let row = stmt
            .query_row(
                params![self.namespace(), dir_ino.as_slice(), name],
                file_from_row,
            )
            .optional()?;
        Ok(row)
    }

    /// One content version.
    fn version(&self, ino: Ino, version: u64) -> Result<Option<VersionRecord>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {VERSION_COLUMNS} FROM mm_versions
             WHERE namespace = ?1 AND ino = ?2 AND version = ?3"
        ))?;
        let row = stmt
            .query_row(
                params![self.namespace(), ino.as_slice(), to_i64(version)?],
                version_from_row,
            )
            .optional()?;
        Ok(row)
    }

    /// The ordered chunk list of one version.
    fn version_chunks(&self, ino: Ino, version: u64) -> Result<Vec<ChunkRef>> {
        let mut stmt = self.conn().prepare(
            "SELECT chunk_no, chunk_hash, offset, len FROM mm_version_chunks
             WHERE namespace = ?1 AND ino = ?2 AND version = ?3 ORDER BY chunk_no",
        )?;
        let rows = stmt.query_map(
            params![self.namespace(), ino.as_slice(), to_i64(version)?],
            |row| {
                Ok(ChunkRef {
                    chunk_no: row_u32(row, 0)?,
                    hash: blob32(row, 1)?,
                    offset: row_u64(row, 2)?,
                    len: row_u32(row, 3)?,
                })
            },
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// The bytes of one content-addressed chunk.
    fn chunk(&self, hash: Hash) -> Result<Option<Vec<u8>>> {
        let data: Option<Vec<u8>> = self
            .conn()
            .query_row(
                "SELECT data FROM mm_chunks WHERE hash = ?1",
                params![hash.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(data)
    }

    /// The stored base snapshot of one directory, in name order.
    fn base_manifest(&self, dir_ino: Ino) -> Result<Vec<ManifestEntry>> {
        let mut stmt = self.conn().prepare(
            "SELECT name, ino, kind, mode, uid, gid, mtime_ns, size, file_root,
                    content_hash, target
             FROM mm_base WHERE namespace = ?1 AND dir_ino = ?2 ORDER BY name",
        )?;
        let rows = stmt.query_map(params![self.namespace(), dir_ino.as_slice()], |row| {
            Ok(ManifestEntry {
                name: row.get(0)?,
                ino: blob16(row, 1)?,
                kind: EntryKind::parse(&row.get::<_, String>(2)?)
                    .ok_or_else(|| invalid_column(2, "unknown entry kind"))?,
                op: EntryOp::Keep,
                from_name: None,
                mode: row_u32(row, 3)?,
                uid: row_u32(row, 4)?,
                gid: row_u32(row, 5)?,
                mtime_ns: row.get(6)?,
                size: row_u64(row, 7)?,
                file_root: blob32(row, 8)?,
                content_hash: optional_blob32(row, 9)?,
                target: row.get(10)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// The `manifest_hash` of the stored base snapshot.
    fn base_manifest_hash(&self, dir_ino: Ino) -> Result<Hash> {
        let manifest = Manifest::from_base_entries(self.base_manifest(dir_ino)?)?;
        Ok(manifest.hash())
    }

    /// One upload session.
    fn upload(&self, batch_id: BatchId) -> Result<Option<UploadRecord>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {UPLOAD_COLUMNS} FROM mm_uploads
             WHERE namespace = ?1 AND batch_id = ?2"
        ))?;
        let row = stmt
            .query_row(
                params![self.namespace(), batch_id.as_bytes().as_slice()],
                upload_from_row,
            )
            .optional()?;
        Ok(row)
    }

    /// Every upload session owned by one lock.
    fn uploads_for_lock(&self, lock_id: LockId) -> Result<Vec<UploadRecord>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {UPLOAD_COLUMNS} FROM mm_uploads
             WHERE namespace = ?1 AND lock_id = ?2 ORDER BY created_at_ms"
        ))?;
        let rows = stmt.query_map(
            params![self.namespace(), lock_id.as_bytes().as_slice()],
            upload_from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// One lock by id.
    fn lock(&self, lock_id: LockId) -> Result<Option<LockRecord>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {LOCK_COLUMNS} FROM mm_locks WHERE namespace = ?1 AND lock_id = ?2"
        ))?;
        let row = stmt
            .query_row(
                params![self.namespace(), lock_id.as_bytes().as_slice()],
                lock_from_row,
            )
            .optional()?;
        Ok(row)
    }

    /// One lock by canonical directory path.
    fn lock_for_dir(&self, dir_path: &str) -> Result<Option<LockRecord>> {
        validate_dir_path(dir_path)?;
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {LOCK_COLUMNS} FROM mm_locks WHERE namespace = ?1 AND dir_path = ?2"
        ))?;
        let row = stmt
            .query_row(params![self.namespace(), dir_path], lock_from_row)
            .optional()?;
        Ok(row)
    }

    /// One committed batch by id.
    fn batch(&self, batch_id: BatchId) -> Result<Option<BatchRecord>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {BATCH_COLUMNS} FROM mm_batches
             WHERE namespace = ?1 AND batch_id = ?2"
        ))?;
        let row = stmt
            .query_row(
                params![self.namespace(), batch_id.as_bytes().as_slice()],
                batch_from_row,
            )
            .optional()?;
        Ok(row)
    }

    /// One committed batch by its global snapshot sequence.
    fn batch_by_snapshot(&self, seq: MmSeq) -> Result<Option<BatchRecord>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {BATCH_COLUMNS} FROM mm_batches
             WHERE namespace = ?1 AND snapshot_seq = ?2"
        ))?;
        let row = stmt
            .query_row(
                params![self.namespace(), to_i64(seq.get())?],
                batch_from_row,
            )
            .optional()?;
        Ok(row)
    }
}

fn open_reader(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(Duration::from_millis(schema::BUSY_TIMEOUT_MS))?;
    conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA query_only = ON;")?;
    Ok(conn)
}

fn invalid_column(index: usize, message: &'static str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        rusqlite::types::Type::Text,
        Box::new(MmError::Corrupt(message)),
    )
}

fn blob16(row: &Row<'_>, index: usize) -> rusqlite::Result<Ino> {
    let value: Vec<u8> = row.get(index)?;
    value
        .try_into()
        .map_err(|_| invalid_column(index, "blob is not 16 bytes"))
}

fn blob32(row: &Row<'_>, index: usize) -> rusqlite::Result<Hash> {
    let value: Vec<u8> = row.get(index)?;
    value
        .try_into()
        .map_err(|_| invalid_column(index, "blob is not 32 bytes"))
}

fn optional_blob16(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<Ino>> {
    let value: Option<Vec<u8>> = row.get(index)?;
    value
        .map(|bytes| {
            bytes
                .try_into()
                .map_err(|_| invalid_column(index, "blob is not 16 bytes"))
        })
        .transpose()
}

fn optional_blob32(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<Hash>> {
    let value: Option<Vec<u8>> = row.get(index)?;
    value
        .map(|bytes| {
            bytes
                .try_into()
                .map_err(|_| invalid_column(index, "blob is not 32 bytes"))
        })
        .transpose()
}

fn blob32_value(value: Vec<u8>) -> Result<Hash> {
    value
        .try_into()
        .map_err(|_| MmError::Corrupt("blob is not 32 bytes"))
}

fn row_u64(row: &Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| invalid_column(index, "negative integer"))
}

fn row_u32(row: &Row<'_>, index: usize) -> rusqlite::Result<u32> {
    let value: i64 = row.get(index)?;
    u32::try_from(value).map_err(|_| invalid_column(index, "integer is outside u32"))
}

fn validate_epoch(epoch: u64) -> Result<()> {
    if epoch == 0 {
        return Err(MmError::Invalid("epoch must be at least 1"));
    }
    Ok(())
}

fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| MmError::Invalid("integer does not fit i64"))
}

fn dir_from_row(row: &Row<'_>) -> rusqlite::Result<DirRecord> {
    Ok(DirRecord {
        ino: blob16(row, 0)?,
        path: row.get(1)?,
        base: MmBase {
            epoch: row_u64(row, 2)?,
            dir_seq: DirSeq::new(row_u64(row, 3)?),
            dir_version: blob32(row, 4)?,
        },
        phase: Phase::parse(&row.get::<_, String>(5)?)
            .ok_or_else(|| invalid_column(5, "unknown directory phase"))?,
        attrs: DirAttrs {
            mode: row_u32(row, 6)?,
            uid: row_u32(row, 7)?,
            gid: row_u32(row, 8)?,
            mtime_ns: row.get(9)?,
        },
        deleted: row.get::<_, i64>(10)? != 0,
        created_at_ms: row.get(11)?,
        updated_at_ms: row.get(12)?,
    })
}

fn file_from_row(row: &Row<'_>) -> rusqlite::Result<FileRecord> {
    Ok(FileRecord {
        ino: blob16(row, 0)?,
        dir_ino: blob16(row, 1)?,
        name: row.get(2)?,
        kind: EntryKind::parse(&row.get::<_, String>(3)?)
            .ok_or_else(|| invalid_column(3, "unknown entry kind"))?,
        attrs: DirAttrs {
            mode: row_u32(row, 4)?,
            uid: row_u32(row, 5)?,
            gid: row_u32(row, 6)?,
            mtime_ns: row.get(7)?,
        },
        size: row_u64(row, 8)?,
        file_root: blob32(row, 9)?,
        content_hash: optional_blob32(row, 10)?,
        target: row.get(11)?,
        version: row_u64(row, 12)?,
        deleted: row.get::<_, i64>(13)? != 0,
        created_at_ms: row.get(14)?,
        updated_at_ms: row.get(15)?,
    })
}

fn version_from_row(row: &Row<'_>) -> rusqlite::Result<VersionRecord> {
    Ok(VersionRecord {
        ino: blob16(row, 0)?,
        version: row_u64(row, 1)?,
        size: row_u64(row, 2)?,
        file_root: blob32(row, 3)?,
        content_hash: blob32(row, 4)?,
        chunk_count: row_u32(row, 5)?,
        created_at_ms: row.get(6)?,
    })
}

fn upload_from_row(row: &Row<'_>) -> rusqlite::Result<UploadRecord> {
    Ok(UploadRecord {
        batch_id: BatchId::from_bytes(blob16(row, 0)?),
        lock_id: LockId::from_bytes(blob16(row, 1)?),
        dir_path: row.get(2)?,
        dir_ino: blob16(row, 3)?,
        base_epoch: row_u64(row, 4)?,
        base_seq: DirSeq::new(row_u64(row, 5)?),
        dir_version: blob32(row, 6)?,
        manifest_hash: blob32(row, 7)?,
        state: UploadState::parse(&row.get::<_, String>(8)?)
            .ok_or_else(|| invalid_column(8, "unknown upload state"))?,
        spool_path: row.get(9)?,
        bytes_received: row_u64(row, 10)?,
        created_at_ms: row.get(11)?,
        updated_at_ms: row.get(12)?,
        expires_at_ms: row.get(13)?,
    })
}

fn lock_from_row(row: &Row<'_>) -> rusqlite::Result<LockRecord> {
    Ok(LockRecord {
        lock_id: LockId::from_bytes(blob16(row, 0)?),
        dir_path: row.get(1)?,
        dir_ino: blob16(row, 2)?,
        owner_client: blob16(row, 3)?,
        owner_session: blob16(row, 4)?,
        base_epoch: row_u64(row, 5)?,
        base_seq: DirSeq::new(row_u64(row, 6)?),
        batch_id: optional_blob16(row, 7)?.map(BatchId::from_bytes),
        expires_at_ms: row.get(8)?,
        created_at_ms: row.get(9)?,
        renewed_at_ms: row.get(10)?,
        progress_bytes: row_u64(row, 11)?,
    })
}

fn batch_from_row(row: &Row<'_>) -> rusqlite::Result<BatchRecord> {
    Ok(BatchRecord {
        batch_id: BatchId::from_bytes(blob16(row, 0)?),
        dir_path: row.get(1)?,
        dir_ino: blob16(row, 2)?,
        base_epoch: row_u64(row, 3)?,
        base_seq: DirSeq::new(row_u64(row, 4)?),
        base_seq_after: DirSeq::new(row_u64(row, 5)?),
        snapshot_seq: MmSeq::new(row_u64(row, 6)?),
        dir_version_before: blob32(row, 7)?,
        dir_version_after: blob32(row, 8)?,
        manifest_hash: blob32(row, 9)?,
        client_id: blob16(row, 10)?,
        entry_count: row_u32(row, 11)?,
        bytes: row_u64(row, 12)?,
        committed_at_ms: row.get(13)?,
    })
}

fn dir_version_from_row(row: &Row<'_>) -> rusqlite::Result<DirVersionRecord> {
    Ok(DirVersionRecord {
        dir_ino: blob16(row, 0)?,
        dir_path: row.get(1)?,
        base_epoch: row_u64(row, 2)?,
        dir_seq: DirSeq::new(row_u64(row, 3)?),
        snapshot_seq: MmSeq::new(row_u64(row, 4)?),
        dir_version: blob32(row, 5)?,
        updated_at_ms: row.get(6)?,
    })
}
