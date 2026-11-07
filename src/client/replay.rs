//! Applying the server's event stream to the client's SQLite tree.
//!
//! One event is one `BEGIN IMMEDIATE` transaction. The transaction updates
//! `objects`/`names`/`chunks`/`object_chunks`, acknowledges the matching
//! outbox row, and advances `meta.applied_seq`. A crash therefore leaves the
//! database either before or after an event, never half-way.
//!
//! # Ordering and idempotence
//!
//! Events arrive in server sequence order. An event at or below
//! `applied_seq` is skipped; every mutation is written with `INSERT`/
//! `UPDATE ... WHERE` semantics that make a repeated application a no-op.
//! A client's own echo matches its outbox by `op_id` and does not apply the
//! local effect again.
//!
//! # Epoch
//!
//! A different epoch means the server compacted or reset. The client clears
//! the replicated tables, resets `applied_seq` to zero, and replays the new
//! stream from the beginning. Pending outbox rows survive: they are local
//! intent and are resent after the replay.

use std::collections::BTreeMap;

use rusqlite::{OptionalExtension, params};

use super::db::{ApplyOutcome, ClientDb, DbError, Ino, OutboxState, now_ns, split_path};
use super::ops::{bump_nlink, validate_name};
use crate::store::Errno;
use crate::store::sqlite::{
    self, ChunkRef, EventKind, EventPayload, Object, ObjectKind, ROOT_INO, ReadTx, WriteTx, keys,
};

/// Report from one seed scan.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SeedReport {
    pub objects: u64,
    pub events: u64,
    pub chunks: u64,
}

impl ClientDb {
    /// Apply one server event.
    ///
    /// `data` is the reassembled `STREAM_DATA` payload for a write, in the
    /// same chunk order as `payload.chunks()`. It is `None` for metadata
    /// events and for a write whose stream has not arrived.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_remote(
        &self,
        seq: i64,
        epoch: i64,
        op_id: Option<[u8; 16]>,
        result: &str,
        payload: &EventPayload,
        path: Option<&str>,
        path2: Option<&str>,
        data: Option<&[u8]>,
    ) -> Result<ApplyOutcome, DbError> {
        let mut db = self.lock_writer();
        let snapshot = db.read()?;
        let applied = snapshot.meta_i64(keys::APPLIED_SEQ)?;
        let current_epoch = snapshot.meta_i64(keys::EPOCH)?;
        if seq <= applied {
            return Ok(ApplyOutcome::Duplicate);
        }
        if seq != applied + 1 {
            return Err(DbError::Corrupt("event sequence gap"));
        }
        if epoch != current_epoch {
            return Err(DbError::Corrupt("event epoch does not match the database"));
        }

        let tx = db.write()?;
        if result != "ok" {
            if let Some(op_id) = op_id {
                // A verdict records the attempt the send path made, even
                // when the verdict crosses that path's own update.
                tx.conn().execute(
                    "UPDATE outbox SET state = 'failed', attempts = MAX(attempts, 1)
                     WHERE op_id = ?1",
                    [op_id.as_slice()],
                )?;
            }
            tx.set_meta_i64(keys::APPLIED_SEQ, seq)?;
            tx.commit()?;
            return Ok(ApplyOutcome::Rejected);
        }

        let acknowledged = match op_id {
            Some(op_id) => Self::ack_outbox(&tx, op_id)?,
            None => Vec::new(),
        };

        match payload {
            EventPayload::CreateFile { .. }
            | EventPayload::CreateDir { .. }
            | EventPayload::Symlink { .. } => {
                let path = path.ok_or(DbError::Corrupt("create event without a path"))?;
                Self::apply_create(&snapshot, &tx, seq, payload, path)?;
            }
            EventPayload::Write {
                ino,
                offset,
                size,
                file_root,
                mtime_ns,
                chunks,
                ..
            } => {
                Self::apply_write(
                    &snapshot, &tx, seq, *ino, *offset, *size, *file_root, *mtime_ns, chunks,
                    data,
                )?;
            }
            EventPayload::Truncate {
                ino,
                size,
                file_root,
                mtime_ns,
            } => {
                Self::apply_truncate(&snapshot, &tx, seq, *ino, *size, *file_root, *mtime_ns)?;
            }
            EventPayload::Setattr {
                ino,
                mode,
                uid,
                gid,
                mtime_ns,
            } => {
                let mut object =
                    Self::object_in(&tx, *ino)?.ok_or(DbError::Errno(Errno::ENOENT))?;
                if let Some(mode) = mode {
                    object.mode = *mode;
                }
                if let Some(uid) = uid {
                    object.uid = *uid;
                }
                if let Some(gid) = gid {
                    object.gid = *gid;
                }
                if let Some(mtime_ns) = mtime_ns {
                    object.mtime_ns = *mtime_ns;
                }
                object.updated_seq = seq;
                tx.put_object(&object)?;
            }
            EventPayload::Rename { ino } => {
                let old_path = path.ok_or(DbError::Corrupt("rename event without a path"))?;
                let new_path =
                    path2.ok_or(DbError::Corrupt("rename event without a destination"))?;
                Self::apply_rename(&snapshot, &tx, seq, *ino, old_path, new_path)?;
            }
            EventPayload::Unlink { ino } | EventPayload::Rmdir { ino } => {
                let path = path.ok_or(DbError::Corrupt("unlink event without a path"))?;
                Self::apply_remove(&snapshot, &tx, seq, *ino, path)?;
            }
            EventPayload::Link { ino } => {
                let path = path2
                    .or(path)
                    .ok_or(DbError::Corrupt("link event without a path"))?;
                Self::apply_link(&snapshot, &tx, seq, *ino, path)?;
            }
            EventPayload::Lock { .. }
            | EventPayload::Unlock { .. }
            | EventPayload::Leave
            | EventPayload::SyncCtrl { .. } => {
                // Advisory locks and control markers have no durable object
                // effect in this client.
            }
        }

        tx.set_meta_i64(keys::APPLIED_SEQ, seq)?;
        tx.set_meta_i64(keys::EPOCH, epoch)?;
        let pending: i64 = tx.conn().query_row(
            "SELECT COUNT(*) FROM outbox WHERE state IN ('pending', 'sent')",
            [],
            |row| row.get(0),
        )?;
        tx.set_meta_i64(keys::DIRTY, i64::from(pending != 0))?;
        if !acknowledged.is_empty() {
            Self::refresh_refcounts(&tx, &acknowledged)?;
        }
        tx.commit()?;
        Ok(ApplyOutcome::Applied)
    }

    /// Delete an outbox row (and any coalesced members stored in `undo`).
    /// Returns the chunk hashes whose refcount must be refreshed.
    fn ack_outbox(tx: &WriteTx<'_>, op_id: [u8; 16]) -> Result<Vec<[u8; 32]>, DbError> {
        let undo: Option<Vec<u8>> = tx
            .conn()
            .query_row("SELECT undo FROM outbox WHERE op_id = ?1", [op_id.as_slice()], |row| {
                row.get::<_, Option<Vec<u8>>>(0)
            })
            .optional()?
            .flatten();
        let mut members = vec![op_id];
        if let Some(bytes) = undo {
            if let Ok(extra) = bincode::serde::decode_from_slice::<Vec<[u8; 16]>, _>(
                &bytes,
                bincode::config::standard(),
            ) {
                members.extend(extra.0);
            }
        }
        let mut hashes = Vec::new();
        for member in members {
            {
                let mut stmt = tx.conn().prepare(
                    "SELECT chunk_hash FROM outbox_chunks WHERE op_id = ?1",
                )?;
                let mut rows = stmt.query([member.as_slice()])?;
                while let Some(row) = rows.next()? {
                    let bytes: Vec<u8> = row.get(0)?;
                    if let Ok(hash) = <[u8; 32]>::try_from(bytes) {
                        hashes.push(hash);
                    }
                }
            }
            tx.conn()
                .execute("DELETE FROM outbox WHERE op_id = ?1", [member.as_slice()])?;
        }
        Ok(hashes)
    }

    fn apply_create(
        snapshot: &ReadTx,
        tx: &WriteTx<'_>,
        seq: i64,
        payload: &EventPayload,
        path: &str,
    ) -> Result<(), DbError> {
        if path == "/" {
            let (mode, uid, gid, mtime_ns) = match payload {
                EventPayload::CreateFile {
                    mode,
                    uid,
                    gid,
                    mtime_ns,
                    ..
                }
                | EventPayload::CreateDir {
                    mode,
                    uid,
                    gid,
                    mtime_ns,
                    ..
                }
                | EventPayload::Symlink {
                    mode,
                    uid,
                    gid,
                    mtime_ns,
                    ..
                } => (*mode, *uid, *gid, *mtime_ns),
                _ => return Err(DbError::Corrupt("not a create payload")),
            };
            let mut root = Self::object_in(tx, ROOT_INO)?
                .ok_or(DbError::Corrupt("root object is missing"))?;
            root.mode = mode;
            root.uid = uid;
            root.gid = gid;
            root.mtime_ns = mtime_ns;
            root.updated_seq = seq;
            tx.put_object(&root)?;
            return Ok(());
        }
        let (parent_path, name) =
            split_path(path).ok_or(DbError::Corrupt("create event at the root"))?;
        let _ = validate_name(std::ffi::OsStr::new(name))?;
        let parent = Self::ino_by_path_in(tx, parent_path)?;
        let (ino, kind, mode, uid, gid, mtime_ns, file_root, target) = match payload {
            EventPayload::CreateFile {
                ino,
                mode,
                uid,
                gid,
                mtime_ns,
                file_root,
            } => (*ino, ObjectKind::File, *mode, *uid, *gid, *mtime_ns, *file_root, None),
            EventPayload::CreateDir {
                ino,
                mode,
                uid,
                gid,
                mtime_ns,
                file_root,
            } => (*ino, ObjectKind::Dir, *mode, *uid, *gid, *mtime_ns, *file_root, None),
            EventPayload::Symlink {
                ino,
                mode,
                uid,
                gid,
                mtime_ns,
                target,
                file_root,
            } => (
                *ino,
                ObjectKind::Symlink,
                *mode,
                *uid,
                *gid,
                *mtime_ns,
                *file_root,
                Some(target.clone()),
            ),
            _ => return Err(DbError::Corrupt("not a create payload")),
        };

        let existing = Self::name_in_read(snapshot, parent, name)?;
        if let Some(existing_ino) = existing {
            if existing_ino != ino {
                // The server's order is authoritative: detach the losing
                // local entry, then link the winner.
                Self::detach_name(snapshot, tx, parent, name, existing_ino, seq)?;
            }
        }

        let size = target.as_ref().map_or(0, |target| target.len() as u64);
        match Self::object_in(tx, ino)? {
            Some(mut object) => {
                object.mode = mode;
                object.uid = uid;
                object.gid = gid;
                object.mtime_ns = mtime_ns;
                object.updated_seq = seq;
                if object.deleted {
                    object.deleted = false;
                    object.nlink = if kind.is_dir() { 2 } else { 1 };
                    object.size = size;
                    object.file_root = file_root;
                    object.block_count = 0;
                    tx.set_object_chunks(ino, &[])?;
                }
                tx.put_object(&object)?;
            }
            None => {
                let object = Object {
                    ino,
                    kind,
                    mode,
                    uid,
                    gid,
                    mtime_ns,
                    size,
                    file_root,
                    block_count: 0,
                    target,
                    nlink: if kind.is_dir() { 2 } else { 1 },
                    deleted: false,
                    created_seq: seq,
                    updated_seq: seq,
                };
                tx.put_object(&object)?;
            }
        }

        let inserted = Self::name_in_tx(tx, parent, name)?.is_none();
        if inserted {
            tx.put_name(parent, name, ino, path)?;
            if kind.is_dir() {
                bump_nlink(tx, parent, 1)?;
            }
        }
        Self::next_fuse_ino(tx, ino)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_write(
        snapshot: &ReadTx,
        tx: &WriteTx<'_>,
        seq: i64,
        ino: Ino,
        offset: u64,
        size: u64,
        file_root: [u8; 32],
        mtime_ns: i64,
        chunks: &[ChunkRef],
        data: Option<&[u8]>,
    ) -> Result<(), DbError> {
        let mut object = Self::object_in(tx, ino)?.ok_or(DbError::Errno(Errno::ENOENT))?;
        if object.deleted {
            return Err(DbError::Errno(Errno::ENOENT));
        }
        let existing = Self::object_chunks_in(tx, ino)?;
        let mut by_no: BTreeMap<u32, ChunkRef> =
            existing.iter().map(|chunk| (chunk.chunk_no, chunk.clone())).collect();

        let mut chunks = chunks.to_vec();
        if chunks.is_empty() {
            if let Some(bytes) = data {
                let base = offset;
                let mut cursor = 0usize;
                let mut chunk_no = (base / u64::from(crate::store::sqlite::CHUNK_BYTES)) as u32;
                while cursor < bytes.len() {
                    let take = (bytes.len() - cursor)
                        .min(crate::store::sqlite::CHUNK_BYTES as usize);
                    let slice = &bytes[cursor..cursor + take];
                    chunks.push(ChunkRef {
                        chunk_no,
                        hash: crate::store::sqlite::chunk_hash(slice),
                        offset: u64::from(chunk_no)
                            * u64::from(crate::store::sqlite::CHUNK_BYTES),
                        len: take as u32,
                    });
                    cursor += take;
                    chunk_no += 1;
                }
            }
        }
        let mut cursor = 0usize;
        for chunk in &chunks {
            let slice = match data {
                Some(bytes) if cursor + chunk.len as usize <= bytes.len() => {
                    let slice = &bytes[cursor..cursor + chunk.len as usize];
                    cursor += chunk.len as usize;
                    Some(slice)
                }
                Some(_) => {
                    return Err(DbError::Corrupt("write stream is shorter than its chunk list"))
                }
                None => None,
            };
            let reference = match slice {
                Some(bytes) => {
                    let hash = crate::store::sqlite::chunk_hash(bytes);
                    if hash != chunk.hash {
                        return Err(DbError::Corrupt("write stream chunk hash mismatch"));
                    }
                    tx.put_chunk(chunk.hash, chunk.len, Some(bytes))?;
                    ChunkRef {
                        chunk_no: chunk.chunk_no,
                        hash: chunk.hash,
                        offset: chunk.offset,
                        len: chunk.len,
                    }
                }
                None => {
                    if Self::chunk_data_in(tx, chunk.hash)?.is_none() {
                        Self::put_chunk_ref_lazy(tx, chunk.chunk_no, chunk.hash, chunk.len)?
                    } else {
                        ChunkRef {
                            chunk_no: chunk.chunk_no,
                            hash: chunk.hash,
                            offset: chunk.offset,
                            len: chunk.len,
                        }
                    }
                }
            };
            by_no.insert(chunk.chunk_no, reference);
        }
        if let Some(bytes) = data {
            if cursor != bytes.len() {
                return Err(DbError::Corrupt("write stream has trailing bytes"));
            }
        }

        let refs = Self::assemble_chunks(tx, size, &by_no)?;
        let computed_root = crate::store::sqlite::file_root(ObjectKind::File, None, &refs);
        object.size = size;
        object.block_count = u32::try_from(refs.len())
            .map_err(|_| DbError::Corrupt("too many chunks"))?;
        object.file_root = if file_root == [0u8; 32] {
            computed_root
        } else {
            file_root
        };
        object.mtime_ns = mtime_ns;
        object.updated_seq = seq;
        tx.put_object(&object)?;
        tx.set_object_chunks(ino, &refs)?;
        let _ = snapshot;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_truncate(
        snapshot: &ReadTx,
        tx: &WriteTx<'_>,
        seq: i64,
        ino: Ino,
        size: u64,
        file_root: [u8; 32],
        mtime_ns: i64,
    ) -> Result<(), DbError> {
        let mut object = Self::object_in(tx, ino)?.ok_or(DbError::Errno(Errno::ENOENT))?;
        let existing = Self::object_chunks_in(tx, ino)?;
        let mut by_no: BTreeMap<u32, ChunkRef> =
            existing.iter().map(|chunk| (chunk.chunk_no, chunk.clone())).collect();
        let keep = size.div_ceil(u64::from(sqlite::CHUNK_BYTES)) as u32;
        by_no.retain(|chunk_no, _| *chunk_no < keep);
        if size > object.size {
            // The prefix is already there; `assemble_chunks` zero-fills the
            // extension.
        } else if size % u64::from(sqlite::CHUNK_BYTES) != 0 {
            let chunk_no = (size / u64::from(sqlite::CHUNK_BYTES)) as u32;
            if let Some(existing) = by_no.get(&chunk_no).cloned() {
                let chunk = snapshot
                    .chunk(existing.hash)?
                    .ok_or(DbError::MissingChunk(existing.hash))?;
                let mut bytes = chunk
                    .data
                    .ok_or(DbError::MissingChunk(existing.hash))?;
                let wanted = (size % u64::from(sqlite::CHUNK_BYTES)) as usize;
                bytes.truncate(wanted);
                let reference = Self::put_chunk_ref(tx, chunk_no, &bytes)?;
                by_no.insert(chunk_no, reference);
            }
        }
        let refs = Self::assemble_chunks(tx, size, &by_no)?;
        let computed_root = crate::store::sqlite::file_root(ObjectKind::File, None, &refs);
        object.size = size;
        object.block_count = u32::try_from(refs.len())
            .map_err(|_| DbError::Corrupt("too many chunks"))?;
        object.file_root = if file_root == [0u8; 32] {
            computed_root
        } else {
            file_root
        };
        object.mtime_ns = mtime_ns;
        object.updated_seq = seq;
        tx.put_object(&object)?;
        tx.set_object_chunks(ino, &refs)?;
        Ok(())
    }

    fn apply_rename(
        snapshot: &ReadTx,
        tx: &WriteTx<'_>,
        seq: i64,
        ino: Ino,
        old_path: &str,
        new_path: &str,
    ) -> Result<(), DbError> {
        let (old_parent_path, old_name) =
            split_path(old_path).ok_or(DbError::Corrupt("rename of the root"))?;
        let (new_parent_path, new_name) =
            split_path(new_path).ok_or(DbError::Corrupt("rename to the root"))?;
        let old_parent = Self::ino_by_path_in(tx, old_parent_path)?;
        let new_parent = Self::ino_by_path_in(tx, new_parent_path)?;
        let Some(object) = Self::object_in(tx, ino)? else {
            return Ok(());
        };
        if object.deleted {
            return Ok(());
        }
        let old_entry = Self::name_in_tx(tx, old_parent, old_name)?;
        let new_entry = Self::name_in_tx(tx, new_parent, new_name)?;
        if old_entry.is_none() && new_entry == Some(ino) {
            return Ok(());
        }
        if let Some(target) = new_entry {
            if target != ino {
                Self::detach_name(snapshot, tx, new_parent, new_name, target, seq)?;
            }
        }
        if old_entry.is_some() {
            tx.delete_name(old_parent, old_name)?;
            if object.kind.is_dir() {
                Self::rewrite_subtree_paths(tx, old_path, new_path)?;
                if old_parent != new_parent {
                    bump_nlink(tx, old_parent, -1)?;
                    bump_nlink(tx, new_parent, 1)?;
                }
            }
        }
        if Self::name_in_tx(tx, new_parent, new_name)?.is_none() {
            tx.put_name(new_parent, new_name, ino, new_path)?;
        }
        Self::next_fuse_ino(tx, ino)?;
        Ok(())
    }

    fn apply_remove(
        snapshot: &ReadTx,
        tx: &WriteTx<'_>,
        seq: i64,
        ino: Ino,
        path: &str,
    ) -> Result<(), DbError> {
        let (parent_path, name) =
            split_path(path).ok_or(DbError::Corrupt("unlink of the root"))?;
        let parent = Self::ino_by_path_in(tx, parent_path)?;
        match Self::name_in_tx(tx, parent, name)? {
            None => return Ok(()),
            Some(existing) if existing != ino => {
                Self::detach_name(snapshot, tx, parent, name, existing, seq)?;
                return Ok(());
            }
            Some(_) => {}
        }
        let object = Self::object_in(tx, ino)?.ok_or(DbError::Errno(Errno::ENOENT))?;
        tx.delete_name(parent, name)?;
        if object.kind.is_dir() {
            bump_nlink(tx, parent, -1)?;
        }
        let mut updated = object;
        updated.nlink = updated.nlink.saturating_sub(1);
        if updated.nlink == 0 {
            tx.set_object_chunks(ino, &[])?;
            updated.deleted = true;
            updated.nlink = 0;
        }
        updated.updated_seq = seq;
        tx.put_object(&updated)?;
        Ok(())
    }

    fn apply_link(
        snapshot: &ReadTx,
        tx: &WriteTx<'_>,
        seq: i64,
        ino: Ino,
        path: &str,
    ) -> Result<(), DbError> {
        let (parent_path, name) =
            split_path(path).ok_or(DbError::Corrupt("link at the root"))?;
        let parent = Self::ino_by_path_in(tx, parent_path)?;
        if Self::name_in_tx(tx, parent, name)?.is_some() {
            return Ok(());
        }
        let mut object = Self::object_in(tx, ino)?.ok_or(DbError::Errno(Errno::ENOENT))?;
        if object.deleted {
            return Err(DbError::Errno(Errno::ENOENT));
        }
        object.nlink = object.nlink.saturating_add(1);
        object.updated_seq = seq;
        tx.put_object(&object)?;
        tx.put_name(parent, name, ino, path)?;
        Self::next_fuse_ino(tx, ino)?;
        let _ = snapshot;
        Ok(())
    }

    /// Detach a losing name and tombstone its object when the last link goes.
    fn detach_name(
        snapshot: &ReadTx,
        tx: &WriteTx<'_>,
        parent: Ino,
        name: &str,
        ino: Ino,
        seq: i64,
    ) -> Result<(), DbError> {
        tx.delete_name(parent, name)?;
        let Some(mut object) = Self::object_in(tx, ino)? else {
            return Ok(());
        };
        if object.kind.is_dir() {
            bump_nlink(tx, parent, -1)?;
        }
        object.nlink = object.nlink.saturating_sub(1);
        if object.nlink == 0 {
            tx.set_object_chunks(ino, &[])?;
            object.deleted = true;
            object.nlink = 0;
        }
        object.updated_seq = seq;
        tx.put_object(&object)?;
        let _ = snapshot;
        Ok(())
    }

    fn name_in_tx(tx: &WriteTx<'_>, parent: Ino, name: &str) -> Result<Option<Ino>, DbError> {
        let bytes: Option<Vec<u8>> = tx
            .conn()
            .query_row(
                "SELECT ino FROM names WHERE parent = ?1 AND name = ?2",
                params![parent.as_slice(), name],
                |row| row.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| {
                bytes
                    .try_into()
                    .map_err(|_| DbError::Corrupt("names.ino is not 16 bytes"))
            })
            .transpose()
    }

    fn name_in_read(tx: &ReadTx, parent: Ino, name: &str) -> Result<Option<Ino>, DbError> {
        let bytes: Option<Vec<u8>> = tx
            .conn()
            .query_row(
                "SELECT ino FROM names WHERE parent = ?1 AND name = ?2",
                params![parent.as_slice(), name],
                |row| row.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| {
                bytes
                    .try_into()
                    .map_err(|_| DbError::Corrupt("names.ino is not 16 bytes"))
            })
            .transpose()
    }


    /// Record the server epoch without clearing the local tree.
    ///
    /// The first client of an empty server keeps its tree and seeds it; only
    /// its epoch marker changes.
    pub fn set_epoch(&self, epoch: i64) -> Result<(), DbError> {
        self.write(|tx| {
            tx.set_meta_i64(keys::EPOCH, epoch)?;
            Ok(())
        })
    }

    /// Clear the replicated tables for a new server epoch.
    ///
    /// The outbox survives: those are local intentions that will be resent
    /// after the replay. `applied_seq` restarts at zero.
    pub fn reset_epoch(&self, epoch: i64) -> Result<(), DbError> {
        self.write(|tx| {
            tx.conn().execute("DELETE FROM object_chunks", [])?;
            tx.conn().execute("DELETE FROM names", [])?;
            tx.conn().execute("DELETE FROM objects WHERE ino <> ?1", [ROOT_INO.as_slice()])?;
            tx.conn().execute(
                "DELETE FROM chunks WHERE hash NOT IN (SELECT chunk_hash FROM outbox_chunks)",
                [],
            )?;
            tx.conn().execute("DELETE FROM events", [])?;
            tx.conn().execute(
                "DELETE FROM fuse_inos WHERE ino <> ?1",
                [ROOT_INO.as_slice()],
            )?;
            tx.conn().execute("UPDATE outbox SET state = 'pending'", [])?;
            let root = Object {
                ino: ROOT_INO,
                kind: ObjectKind::Dir,
                mode: 0o755,
                uid: 0,
                gid: 0,
                mtime_ns: 0,
                size: 0,
                file_root: crate::store::sqlite::file_root(ObjectKind::Dir, None, &[]),
                block_count: 0,
                target: None,
                nlink: 2,
                deleted: false,
                created_seq: 0,
                updated_seq: 0,
            };
            tx.put_object(&root)?;
            tx.set_meta_i64(keys::FUSE_INO_NEXT, 2)?;
            tx.set_meta_i64(keys::EPOCH, epoch)?;
            tx.set_meta_i64(keys::APPLIED_SEQ, 0)?;
            tx.set_meta_i64(keys::COVERED_SEQ, 0)?;
            tx.set_meta_i64(keys::DIRTY, 1)?;
            Ok(())
        })
    }

    /// Serialize the local tree into outbox events for an empty server.
    ///
    /// A create uses the object's inode as its operation id because the server
    /// derives the created inode from that id; write and link ids stay
    /// deterministic (`epoch || path || kind`), so an interrupted upload can
    /// be retried. The local tree is not cleared: the echo of each event
    /// acknowledges the row and leaves the state unchanged.
    pub fn seed(&self, epoch: i64) -> Result<SeedReport, DbError> {
        let mut db = self.lock_writer();
        let snapshot = db.read()?;
        let live = collect_live(&snapshot)?;
        let mut desired = Vec::new();
        for item in &live {
            // The server derives a create's inode from its op id. Reuse the
            // object's stable local inode as the op id so both ends agree;
            // the deterministic path hash is only a fallback for a zero ino.
            let op_id = if item.object.ino == [0u8; 16] {
                seed_op_id("object", epoch, &item.path)
            } else {
                item.object.ino
            };
            let payload = match item.object.kind {
                ObjectKind::File => EventPayload::CreateFile {
                    ino: item.object.ino,
                    mode: item.object.mode,
                    uid: item.object.uid,
                    gid: item.object.gid,
                    mtime_ns: item.object.mtime_ns,
                    file_root: crate::store::sqlite::file_root(ObjectKind::File, None, &[]),
                },
                ObjectKind::Dir => EventPayload::CreateDir {
                    ino: item.object.ino,
                    mode: item.object.mode,
                    uid: item.object.uid,
                    gid: item.object.gid,
                    mtime_ns: item.object.mtime_ns,
                    file_root: item.object.file_root,
                },
                ObjectKind::Symlink => EventPayload::Symlink {
                    ino: item.object.ino,
                    mode: item.object.mode,
                    uid: item.object.uid,
                    gid: item.object.gid,
                    mtime_ns: item.object.mtime_ns,
                    target: item.object.target.clone().unwrap_or_default(),
                    file_root: item.object.file_root,
                },
                _ => continue,
            };
            desired.push(SeedRow {
                op_id,
                payload,
                path: item.path.clone(),
                path2: None,
                chunks: Vec::new(),
            });
            if item.object.kind.is_file() && !item.chunks.is_empty() {
                let write_id = seed_op_id("write", epoch, &item.path);
                let payload = EventPayload::Write {
                    ino: item.object.ino,
                    offset: 0,
                    len: item.object.size,
                    size: item.object.size,
                    file_root: item.object.file_root,
                    mtime_ns: item.object.mtime_ns,
                    chunks: item.chunks.clone(),
                };
                desired.push(SeedRow {
                    op_id: write_id,
                    payload,
                    path: item.path.clone(),
                    path2: None,
                    chunks: item.chunks.clone(),
                });
            }
            for extra in &item.extra_paths {
                let link_id = seed_op_id("link", epoch, extra);
                let payload = EventPayload::Link {
                    ino: item.object.ino,
                };
                desired.push(SeedRow {
                    op_id: link_id,
                    payload,
                    path: item.path.clone(),
                    path2: Some(extra.clone()),
                    chunks: Vec::new(),
                });
            }
        }

        // A repeated seed is a no-op when the outbox already holds exactly
        // this event set. Any other outbox content is local intent that the
        // snapshot now represents, so the rows below replace it wholesale.
        let existing = outbox_signature(&snapshot)?;
        let already_seeded = !existing.is_empty() && existing.len() == desired.len() && {
            let mut by_id = BTreeMap::new();
            for row in &desired {
                by_id.insert(row.op_id, row);
            }
            existing.iter().all(|row| {
                row.state != OutboxState::Failed
                    && by_id.get(&row.op_id).is_some_and(|desired| {
                        row.kind == desired.payload.kind()
                            && row.path.as_deref() == Some(desired.path.as_str())
                            && row.path2 == desired.path2
                            && desired
                                .payload
                                .encode()
                                .is_ok_and(|bytes| bytes == row.payload)
                    })
            })
        };
        if already_seeded {
            return Ok(SeedReport::default());
        }

        let tx = db.write()?;
        tx.conn().execute("DELETE FROM outbox", [])?;
        let mut report = SeedReport::default();
        for row in &desired {
            let seq = Self::next_local_seq(&tx)?;
            Self::enqueue(
                &tx,
                row.op_id,
                &row.payload,
                Some(&row.path),
                row.path2.as_deref(),
                &row.chunks,
                seq,
            )?;
            match row.payload.kind() {
                EventKind::CreateFile | EventKind::CreateDir | EventKind::Symlink => {
                    report.objects += 1;
                    report.events += 1;
                }
                EventKind::Write => {
                    report.events += 1;
                    report.chunks += row.chunks.len() as u64;
                }
                _ => report.events += 1,
            }
        }
        tx.conn().execute(
            "UPDATE chunks SET refcount =
               (SELECT COUNT(*) FROM object_chunks oc WHERE oc.chunk_hash = chunks.hash)
             + (SELECT COUNT(*) FROM outbox_chunks x WHERE x.chunk_hash = chunks.hash)",
            [],
        )?;
        tx.commit()?;
        Ok(report)
    }
}

struct LiveObject {
    path: String,
    object: Object,
    chunks: Vec<ChunkRef>,
    extra_paths: Vec<String>,
}

/// One event a seed would enqueue.
struct SeedRow {
    op_id: [u8; 16],
    payload: EventPayload,
    path: String,
    path2: Option<String>,
    chunks: Vec<ChunkRef>,
}

/// The identity and content of one existing outbox row.
struct OutboxSignature {
    op_id: [u8; 16],
    kind: EventKind,
    path: Option<String>,
    path2: Option<String>,
    payload: Vec<u8>,
    state: OutboxState,
}

fn outbox_signature(tx: &ReadTx) -> Result<Vec<OutboxSignature>, DbError> {
    let mut stmt = tx
        .conn()
        .prepare("SELECT op_id, kind, path, path2, payload, state FROM outbox")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let bytes: Vec<u8> = row.get(0)?;
        let op_id: [u8; 16] = bytes
            .try_into()
            .map_err(|_| DbError::Corrupt("outbox.op_id is not 16 bytes"))?;
        let kind_text: String = row.get(1)?;
        let kind = EventKind::parse(&kind_text).ok_or(DbError::Corrupt("unknown outbox kind"))?;
        let state_text: String = row.get(5)?;
        let state =
            OutboxState::parse(&state_text).ok_or(DbError::Corrupt("unknown outbox state"))?;
        out.push(OutboxSignature {
            op_id,
            kind,
            path: row.get(2)?,
            path2: row.get(3)?,
            payload: row.get(4)?,
            state,
        });
    }
    Ok(out)
}

fn collect_live(tx: &ReadTx) -> Result<Vec<LiveObject>, DbError> {
    let mut out = Vec::new();
    {
        let mut stmt = tx.conn().prepare(
            "SELECT MIN(n.path) AS path, o.ino, o.kind, o.mode, o.uid, o.gid, o.mtime_ns,
                    o.size, o.file_root, o.block_count, o.target, o.nlink, o.deleted,
                    o.created_seq, o.updated_seq
             FROM objects o JOIN names n ON n.ino = o.ino
             WHERE o.deleted = 0
             GROUP BY o.ino
             ORDER BY path",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let path: String = row.get(0)?;
            let object = super::db::object_from_row_offset(row, 1)?;
            out.push(LiveObject {
                path,
                object,
                chunks: Vec::new(),
                extra_paths: Vec::new(),
            });
        }
    }
    for item in &mut out {
        item.chunks = tx.object_chunks(item.object.ino)?;
        let mut stmt = tx
            .conn()
            .prepare("SELECT path FROM names WHERE ino = ?1 ORDER BY path")?;
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

fn seed_op_id(kind: &str, epoch: i64, path: &str) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sm/v2/seed\0");
    hasher.update(kind.as_bytes());
    hasher.update(&[0]);
    hasher.update(&epoch.to_le_bytes());
    hasher.update(path.as_bytes());
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest.as_bytes()[..16]);
    if id == [0u8; 16] {
        id[0] = 1;
    }
    id
}

impl ClientDb {
    /// Number of outbox rows still waiting for an echo.
    pub fn pending_outbox(&self) -> Result<u64, DbError> {
        let tx = self.read()?;
        let count: i64 = tx.conn().query_row(
            "SELECT COUNT(*) FROM outbox WHERE state IN ('pending', 'sent')",
            [],
            |row| row.get(0),
        )?;
        Ok(count.max(0) as u64)
    }

    /// `true` when no local operation is outstanding.
    pub fn outbox_empty(&self) -> Result<bool, DbError> {
        Ok(self.pending_outbox()? == 0)
    }

    /// Time of the last local checkpoint, for diagnostics.
    pub fn last_checkpoint_at(&self) -> Result<i64, DbError> {
        let tx = self.read()?;
        Ok(tx.meta_i64(keys::LAST_CHECKPOINT_AT).unwrap_or(0))
    }

    /// Store a chunk received on the wire but not yet referenced by an event.
    pub fn cache_chunk(&self, hash: [u8; 32], data: &[u8]) -> Result<(), DbError> {
        let len = u32::try_from(data.len()).map_err(|_| DbError::Corrupt("chunk too large"))?;
        self.write(|tx| {
            tx.put_chunk(hash, len, Some(data))?;
            Ok(())
        })
    }

    /// Advance the local checkpoint marker. `applied_seq` is unchanged; this
    /// only records that the state tables are the base for later replay.
    pub fn mark_checkpoint(&self) -> Result<(), DbError> {
        let applied = self.applied_seq()?;
        self.write(|tx| {
            tx.set_meta_i64(keys::COVERED_SEQ, applied)?;
            tx.set_meta_i64(keys::LAST_CHECKPOINT_AT, now_ns() / 1_000_000_000)?;
            Ok(())
        })
    }

    /// Outbox rows in send order.
    pub fn outbox_page(&self, limit: usize) -> Result<Vec<super::db::OutboxOp>, DbError> {
        let tx = self.read()?;
        let mut stmt = tx.conn().prepare(
            "SELECT op_id, kind, path, path2, ino, payload, state, created_at
             FROM outbox WHERE state = 'pending'
             ORDER BY created_at LIMIT ?1",
        )?;
        let mut rows = stmt.query([limit as i64])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let bytes: Vec<u8> = row.get(0)?;
            let op_id: [u8; 16] = bytes
                .try_into()
                .map_err(|_| DbError::Corrupt("outbox.op_id is not 16 bytes"))?;
            let kind_text: String = row.get(1)?;
            let kind = crate::store::sqlite::EventKind::parse(&kind_text)
                .ok_or(DbError::Corrupt("unknown outbox kind"))?;
            let path: Option<String> = row.get(2)?;
            let path2: Option<String> = row.get(3)?;
            let ino: Option<Vec<u8>> = row.get(4)?;
            let payload: Vec<u8> = row.get(5)?;
            let state_text: String = row.get(6)?;
            let state = OutboxState::parse(&state_text)
                .ok_or(DbError::Corrupt("unknown outbox state"))?;
            let seq: i64 = row.get(7)?;
            let decoded = EventPayload::decode(kind, &payload)?;
            out.push(super::db::OutboxOp {
                op_id,
                seq,
                kind,
                path,
                path2,
                ino: ino.and_then(|bytes| bytes.try_into().ok()),
                payload,
                decoded,
                state,
            });
        }
        Ok(out)
    }

    /// Chunk bytes referenced by one outbox row, in wire order.
    pub fn outbox_chunks(&self, op_id: [u8; 16]) -> Result<Vec<super::db::OutboxChunk>, DbError> {
        let tx = self.read()?;
        let mut stmt = tx.conn().prepare(
            "SELECT x.chunk_no, x.chunk_hash, x.offset, x.len, c.data
             FROM outbox_chunks x JOIN chunks c ON c.hash = x.chunk_hash
             WHERE x.op_id = ?1 ORDER BY x.chunk_no",
        )?;
        let mut rows = stmt.query([op_id.as_slice()])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let chunk_no: i64 = row.get(0)?;
            let bytes: Vec<u8> = row.get(1)?;
            let hash: [u8; 32] = bytes
                .try_into()
                .map_err(|_| DbError::Corrupt("chunk hash is not 32 bytes"))?;
            let offset: i64 = row.get(2)?;
            let len: i64 = row.get(3)?;
            let data: Option<Vec<u8>> = row.get(4)?;
            out.push(super::db::OutboxChunk {
                chunk_no: u32::try_from(chunk_no)
                    .map_err(|_| DbError::Corrupt("chunk_no out of range"))?,
                hash,
                offset: u64::try_from(offset)
                    .map_err(|_| DbError::Corrupt("chunk offset out of range"))?,
                len: u32::try_from(len).map_err(|_| DbError::Corrupt("chunk len out of range"))?,
                data,
            });
        }
        Ok(out)
    }

    /// Mark rows sent, and record the coalesced members on the first row.
    pub fn mark_sent(
        &self,
        op_id: [u8; 16],
        members: &[[u8; 16]],
    ) -> Result<(), DbError> {
        self.write(|tx| {
            if members.len() > 1 {
                let bytes = bincode::serde::encode_to_vec(
                    members.to_vec(),
                    bincode::config::standard(),
                )
                .map_err(|_| DbError::Corrupt("cannot encode coalesced members"))?;
                tx.conn().execute(
                    "UPDATE outbox SET undo = ?2 WHERE op_id = ?1 AND state = 'pending'",
                    params![op_id.as_slice(), bytes],
                )?;
            }
            // Only a pending row becomes sent. A row already marked failed by
            // a rejection must keep its tombstone even when the rejection
            // crosses this update.
            let mut stmt = tx.conn().prepare(
                "UPDATE outbox SET state = 'sent', attempts = attempts + 1
                 WHERE op_id = ?1 AND state = 'pending'",
            )?;
            for member in members {
                stmt.execute([member.as_slice()])?;
            }
            Ok(())
        })
    }

    /// Reset `sent` back to `pending` after a crash or a new connection.
    pub fn reset_sent(&self) -> Result<(), DbError> {
        self.write(|tx| {
            tx.conn()
                .execute("UPDATE outbox SET state = 'pending' WHERE state = 'sent'", [])?;
            Ok(())
        })
    }

    /// Mark one operation failed after a semantic rejection.
    pub fn reject_op(&self, op_id: [u8; 16], errno: i32) -> Result<(), DbError> {
        let updated = self.write(|tx| {
            Ok(tx.conn().execute(
                "UPDATE outbox SET state = 'failed', attempts = MAX(attempts, 1), undo = ?2
                 WHERE op_id = ?1",
                params![op_id.as_slice(), errno.to_le_bytes().to_vec()],
            )?)
        })?;
        if updated == 0 {
            tracing::warn!(
                event = "reject",
                op = ?op_id,
                errno,
                "rejection names no outbox row"
            );
        } else {
            tracing::info!(
                event = "reject",
                op = ?op_id,
                errno,
                "server rejected the operation"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::client::db::{ClientDb, DbError};
    use crate::client::ops::CreateAttrs;
    use crate::store::sqlite::{ChunkRef, EventPayload, ObjectKind, ROOT_INO};
    use std::ffi::OsStr;

    fn open() -> (tempfile::TempDir, ClientDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = ClientDb::open(dir.path().join("client.db"), [9u8; 16]).unwrap();
        (dir, db)
    }

    fn write_payload(ino: Ino, data: &[u8]) -> (EventPayload, Vec<ChunkRef>) {
        let mut chunks = Vec::new();
        let mut offset = 0u64;
        let mut chunk_no = 0u32;
        while offset < data.len() as u64 {
            let end = ((offset as usize) + crate::store::sqlite::CHUNK_BYTES as usize).min(data.len());
            let bytes = &data[offset as usize..end];
            chunks.push(ChunkRef {
                chunk_no,
                hash: crate::store::sqlite::chunk_hash(bytes),
                offset,
                len: bytes.len() as u32,
            });
            offset = end as u64;
            chunk_no += 1;
        }
        let file_root = crate::store::sqlite::file_root(ObjectKind::File, None, &chunks);
        (
            EventPayload::Write {
                ino,
                offset: 0,
                len: data.len() as u64,
                size: data.len() as u64,
                file_root,
                mtime_ns: 1,
                chunks: chunks.clone(),
            },
            chunks,
        )
    }

    #[test]
    fn replay_applies_and_skips_duplicates() {
        let (_dir, db) = open();
        let ino = [1u8; 16];
        let create = EventPayload::CreateFile {
            ino,
            mode: 0o644,
            uid: 1,
            gid: 2,
            mtime_ns: 1,
            file_root: crate::store::sqlite::file_root(ObjectKind::File, None, &[]),
        };
        let outcome = db
            .apply_remote(1, 1, Some([0xa1; 16]), "ok", &create, Some("/a"), None, None)
            .unwrap();
        assert_eq!(outcome, super::super::db::ApplyOutcome::Applied);
        let (write, _) = write_payload(ino, b"hello");
        let outcome = db
            .apply_remote(2, 1, Some([0xa2; 16]), "ok", &write, Some("/a"), None, Some(b"hello"))
            .unwrap();
        assert_eq!(outcome, super::super::db::ApplyOutcome::Applied);
        assert_eq!(db.read_at(ino, 0, 5).unwrap(), b"hello");
        assert_eq!(db.applied_seq().unwrap(), 2);
        assert_eq!(db.lookup_by_path("/a").unwrap().size, 5);

        let duplicate = db
            .apply_remote(2, 1, Some([0xa2; 16]), "ok", &write, Some("/a"), None, Some(b"hello"))
            .unwrap();
        assert_eq!(duplicate, super::super::db::ApplyOutcome::Duplicate);
        assert_eq!(db.applied_seq().unwrap(), 2);
    }

    #[test]
    fn a_new_epoch_clears_the_replica_but_keeps_the_outbox() {
        let (_dir, db) = open();
        let ino = [2u8; 16];
        let create = EventPayload::CreateDir {
            ino,
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime_ns: 1,
            file_root: crate::store::sqlite::file_root(ObjectKind::Dir, None, &[]),
        };
        db.apply_remote(1, 1, Some([0xb1; 16]), "ok", &create, Some("/d"), None, None)
            .unwrap();
        assert!(db.lookup_by_path("/d").is_ok());
        db.create_file(ino, OsStr::new("local"), CreateAttrs::new(0o644, 0, 0))
            .unwrap();
        let pending = db.outbox_count(super::super::db::OutboxState::Pending).unwrap();
        assert!(pending > 0);

        db.reset_epoch(2).unwrap();
        assert_eq!(db.applied_seq().unwrap(), 0);
        assert_eq!(db.epoch().unwrap(), 2);
        assert!(!db.has_content().unwrap());
        assert_eq!(db.lookup_by_path("/d").unwrap_err().errno(), Errno::ENOENT);
        // Local intent survives; the tree it referred to does not.
        assert_eq!(
            db.outbox_count(super::super::db::OutboxState::Pending).unwrap(),
            pending
        );
    }

    #[test]
    fn seed_is_idempotent_and_replays_into_a_second_database() {
        let (_dir_a, source) = open();
        let dir = source
            .create_dir(ROOT_INO, OsStr::new("d"), CreateAttrs::new(0o755, 0, 0))
            .unwrap();
        let file = source
            .create_file(dir.ino, OsStr::new("f"), CreateAttrs::new(0o644, 7, 8))
            .unwrap();
        source.write_at(file.ino, 0, b"hello world").unwrap();
        let _empty = source
            .create_file(ROOT_INO, OsStr::new("empty"), CreateAttrs::new(0o600, 0, 0))
            .unwrap();
        let _link = source
            .create_symlink(
                ROOT_INO,
                OsStr::new("link"),
                OsStr::new("d/f"),
                CreateAttrs::new(0o777, 0, 0),
            )
            .unwrap();

        let report = source.seed(1).unwrap();
        assert!(report.objects >= 4);
        assert!(report.events >= 5);
        // The pre-seed create/write rows were folded into the snapshot and
        // replaced by the deterministic seed rows.
        assert_eq!(
            source.outbox_count(super::super::db::OutboxState::Pending).unwrap(),
            report.events
        );
        let again = source.seed(1).unwrap();
        assert_eq!(again.events, 0);
        assert_eq!(
            source.outbox_count(super::super::db::OutboxState::Pending).unwrap(),
            report.events
        );

        let (_dir_b, target) = open();
        let rows = source.outbox_page(1000).unwrap();
        assert!(!rows.is_empty());
        for (index, row) in rows.iter().enumerate() {
            let data = if matches!(row.decoded, EventPayload::Write { .. }) {
                let mut bytes = Vec::new();
                for chunk in source.outbox_chunks(row.op_id).unwrap() {
                    bytes.extend_from_slice(chunk.data.as_deref().unwrap());
                }
                Some(bytes)
            } else {
                None
            };
            let outcome = target
                .apply_remote(
                    index as i64 + 1,
                    1,
                    Some(row.op_id),
                    "ok",
                    &row.decoded,
                    row.path.as_deref(),
                    row.path2.as_deref(),
                    data.as_deref(),
                )
                .unwrap();
            assert_eq!(outcome, super::super::db::ApplyOutcome::Applied);
        }
        assert_eq!(target.lookup_by_path("/d/f").unwrap().size, 11);
        assert_eq!(target.read_at(target.lookup_by_path("/d/f").unwrap().ino, 0, 11).unwrap(), b"hello world");
        assert_eq!(target.lookup_by_path("/empty").unwrap().size, 0);
        assert_eq!(
            target.readlink(target.lookup_by_path("/link").unwrap().ino).unwrap(),
            b"d/f"
        );
        assert_eq!(target.applied_seq().unwrap(), rows.len() as i64);
    }

    #[test]
    fn rename_and_unlink_events_follow_the_path() {
        let (_dir, db) = open();
        let dir_ino = [3u8; 16];
        let file_ino = [4u8; 16];
        db.apply_remote(
            1,
            1,
            Some([0xc1; 16]),
            "ok",
            &EventPayload::CreateDir {
                ino: dir_ino,
                mode: 0o755,
                uid: 0,
                gid: 0,
                mtime_ns: 1,
                file_root: crate::store::sqlite::file_root(ObjectKind::Dir, None, &[]),
            },
            Some("/d"),
            None,
            None,
        )
        .unwrap();
        db.apply_remote(
            2,
            1,
            Some([0xc2; 16]),
            "ok",
            &EventPayload::CreateFile {
                ino: file_ino,
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime_ns: 1,
                file_root: crate::store::sqlite::file_root(ObjectKind::File, None, &[]),
            },
            Some("/d/f"),
            None,
            None,
        )
        .unwrap();
        db.apply_remote(
            3,
            1,
            Some([0xc3; 16]),
            "ok",
            &EventPayload::Rename { ino: file_ino },
            Some("/d/f"),
            Some("/d/g"),
            None,
        )
        .unwrap();
        assert_eq!(db.path_of(file_ino).unwrap(), "/d/g");
        db.apply_remote(
            4,
            1,
            Some([0xc4; 16]),
            "ok",
            &EventPayload::Unlink { ino: file_ino },
            Some("/d/g"),
            None,
            None,
        )
        .unwrap();
        assert!(db.lookup_by_path("/d/g").is_err());
        assert!(db.getattr(file_ino).is_err());
        assert!(matches!(db.lookup_by_path("/d/g"), Err(DbError::Errno(Errno::ENOENT))));
    }
}
