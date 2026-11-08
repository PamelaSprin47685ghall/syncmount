//! Applying the server's event stream to the client's SQLite tree.
//!
//! One batch of up to 64 events (or 4 MiB of payload) is one
//! `BEGIN IMMEDIATE` transaction. The transaction updates
//! `objects`/`names`/`chunks`/`object_chunks`, acknowledges the matching
//! outbox rows, and advances `meta.applied_seq` once. A crash therefore leaves
//! the database either before or after the batch, never half-way; an error in
//! any event rolls the whole batch back.
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
use super::ops::{bump_nlink, touch_object, validate_name};
use crate::store::Errno;
use crate::store::sqlite::{
    self, ChunkRef, EventKind, EventPayload, Object, ObjectKind, ROOT_INO, ReadTx, RejectState,
    WriteTx, keys,
};

/// Report from one seed scan.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SeedReport {
    pub objects: u64,
    pub events: u64,
    pub chunks: u64,
}

/// One broken invariant in the replicated tree.
///
/// These are the checks that decide whether the local object/name tables can
/// describe a tree at all. They do not compare attributes with the server;
/// that is what a full replay is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplicaIssue {
    /// The root row is missing, deleted, or not a directory.
    RootMissing,
    /// A live non-root object has no name. The server cannot address it.
    LiveObjectWithoutName { ino: Ino },
    /// A tombstone still has a name.
    DeletedObjectWithName { ino: Ino, path: String },
    /// A name's parent is missing, deleted, or not a directory.
    NameUnderMissingParent { path: String },
    /// A name points at an object row that does not exist.
    NameToMissingObject { path: String },
    /// A name points at a tombstone.
    NameToDeletedObject { path: String },
    /// A name points at the root, which has no directory entry.
    RootHasName { path: String },
    /// A live object's `nlink` does not match its names and children.
    NlinkMismatch { ino: Ino, found: u32, expected: u32 },
    /// A tombstone still carries links.
    DeletedObjectWithLinks { ino: Ino, nlink: u32 },
    /// The denormalized `names.path` does not match the parent chain.
    PathMismatch { stored: String, expected: String },
}

impl ReplicaIssue {
    /// Stable label for logs and tests.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::RootMissing => "root_missing",
            Self::LiveObjectWithoutName { .. } => "live_object_without_name",
            Self::DeletedObjectWithName { .. } => "deleted_object_with_name",
            Self::NameUnderMissingParent { .. } => "name_under_missing_parent",
            Self::NameToMissingObject { .. } => "name_to_missing_object",
            Self::NameToDeletedObject { .. } => "name_to_deleted_object",
            Self::RootHasName { .. } => "root_has_name",
            Self::NlinkMismatch { .. } => "nlink_mismatch",
            Self::DeletedObjectWithLinks { .. } => "deleted_object_with_links",
            Self::PathMismatch { .. } => "path_mismatch",
        }
    }
}

/// What one metadata repair changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReplicaRepair {
    /// Invariants the check found before repairing.
    pub issues: u64,
    /// Root rows recreated because they were missing or not a live directory.
    pub roots: u64,
    /// Live nameless objects turned into tombstones.
    pub tombstones: u64,
    /// Link counts rewritten.
    pub nlinks: u64,
    /// Names removed because their parent or object was gone.
    pub names_removed: u64,
    /// Denormalized paths rewritten.
    pub paths: u64,
}

impl ReplicaRepair {
    /// True when the repair changed something.
    pub const fn changed(&self) -> bool {
        self.roots != 0
            || self.tombstones != 0
            || self.nlinks != 0
            || self.names_removed != 0
            || self.paths != 0
    }
}

/// One `names` row loaded for a consistency pass.
struct ReplicaName {
    parent: Ino,
    name: String,
    ino: Ino,
    path: String,
}

/// `meta` key: server events skipped because the local tree had already
/// applied a later deletion. A growing counter is a divergence signal, not
/// an error: the server's order stays authoritative.
const META_REPLAY_SKIPPED: &str = "replay_skipped";

/// Largest number of events one replay transaction carries.
pub const MAX_BATCH_EVENTS: usize = 64;

/// Largest payload a batch carries before the caller flushes.
pub const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;

/// One server event, ready to join a replay batch.
#[derive(Clone, Debug)]
pub struct RemoteEvent {
    pub seq: i64,
    pub epoch: i64,
    pub op_id: Option<[u8; 16]>,
    /// `"ok"` or a rejection verdict.
    pub result: String,
    pub payload: EventPayload,
    pub path: Option<String>,
    pub path2: Option<String>,
    pub data: Option<Vec<u8>>,
}

impl RemoteEvent {
    /// Approximate memory the event occupies in a batch.
    pub fn batch_bytes(&self) -> usize {
        self.payload
            .encode()
            .map(|encoded| encoded.len())
            .unwrap_or(0)
            + self.data.as_ref().map_or(0, Vec::len)
            + self.path.as_ref().map_or(0, String::len)
            + self.path2.as_ref().map_or(0, String::len)
    }
}

/// What one batch transaction did.
#[derive(Clone, Debug)]
pub struct BatchReport {
    /// One outcome per event the transaction reached. A rejection truncates
    /// this list; the caller must resync before applying later events.
    pub outcomes: Vec<ApplyOutcome>,
    /// The durable watermark after the commit.
    pub applied_seq: i64,
    /// True when the batch stopped at a rejection.
    pub rejected: bool,
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
        let event = RemoteEvent {
            seq,
            epoch,
            op_id,
            result: result.to_owned(),
            payload: payload.clone(),
            path: path.map(str::to_owned),
            path2: path2.map(str::to_owned),
            data: data.map(<[u8]>::to_vec),
        };
        let report = self.apply_remote_batch(&[event])?;
        Ok(report
            .outcomes
            .into_iter()
            .next()
            .unwrap_or(ApplyOutcome::Duplicate))
    }

    /// Apply a contiguous run of server events in one transaction.
    ///
    /// The caller decides the cut (at most [`MAX_BATCH_EVENTS`] events or
    /// [`MAX_BATCH_BYTES`] of payload); this method never splits a batch. One
    /// `BEGIN IMMEDIATE` covers the whole run, so a crash leaves the database
    /// before the batch or after it, never between two events. Every event
    /// still follows the per-event rules: a duplicate is skipped, a gap or an
    /// epoch mismatch fails the transaction, and a rejection records its
    /// verdict and stops the batch.
    ///
    /// `applied_seq` is written once, after the last event, and becomes
    /// durable with the commit. The own-echo ack, the own rename/link
    /// application and the rejection verdict all see the tree as of the
    /// preceding event because they read through the write transaction.
    pub fn apply_remote_batch(&self, events: &[RemoteEvent]) -> Result<BatchReport, DbError> {
        if events.len() > MAX_BATCH_EVENTS {
            return Err(DbError::Corrupt("replay batch is too large"));
        }
        let mut db = self.lock_writer();
        let tx = db.write()?;
        let mut applied = tx.meta_i64(keys::APPLIED_SEQ)?;
        let current_epoch = tx.meta_i64(keys::EPOCH)?;
        let mut outcomes = Vec::with_capacity(events.len());
        let mut acknowledged = Vec::new();
        let mut rejected = false;

        for event in events {
            if event.seq <= applied {
                outcomes.push(ApplyOutcome::Duplicate);
                continue;
            }
            if event.seq != applied + 1 {
                return Err(DbError::Corrupt("event sequence gap"));
            }
            if event.epoch != current_epoch {
                return Err(DbError::Corrupt("event epoch does not match the database"));
            }

            if event.result != "ok" {
                // A verdict records the attempt the send path made, even when
                // the verdict crosses that path's own update. A rejection
                // ends the batch: the caller must resync before applying
                // anything newer.
                if let Some(op_id) = event.op_id {
                    tx.conn().execute(
                        "UPDATE outbox SET state = 'failed', attempts = MAX(attempts, 1)
                         WHERE op_id = ?1",
                        [op_id.as_slice()],
                    )?;
                }
                tx.set_meta_i64(super::db::KEY_NEEDS_RESYNC, 1)?;
                applied = event.seq;
                outcomes.push(ApplyOutcome::Rejected);
                rejected = true;
                break;
            }

            let acknowledged_op = match event.op_id {
                Some(op_id) => Self::ack_outbox(&tx, op_id)?,
                None => None,
            };
            if let Some(hashes) = &acknowledged_op {
                acknowledged.extend_from_slice(hashes);
            }
            // During the post-reset replay the local tree starts empty, so an
            // own event is the only thing that can rebuild it. Apply it like
            // any other event and acknowledge the row; the older-echo hazard
            // does not exist on an empty tree.
            let replaying_local = tx
                .meta_i64(super::db::KEY_REPLAY_LOCAL)
                .unwrap_or(0)
                != 0;
            // Our own echo acknowledges the outbox row. Data operations stay
            // ack-only: the local effect was committed in the same transaction
            // that created that row, and the local state may have advanced past
            // this event (the write buffer can commit several operations before
            // the echo arrives), so applying the older payload would shrink the
            // object and zero-fill chunks that a newer local commit already
            // wrote.
            //
            // Namespace echoes are different. The server resolves paths, so a
            // rename or link may have moved a different inode than the one our
            // optimistic local operation touched. Skipping the echo would leave
            // this replica permanently split from the server, so apply the
            // server's effect to the local tree.
            if acknowledged_op.is_some() && !replaying_local {
                match &event.payload {
                    EventPayload::Rename { ino, mtime_ns } => {
                        let old_path = event
                            .path
                            .as_deref()
                            .ok_or(DbError::Corrupt("rename event without a path"))?;
                        let new_path = event
                            .path2
                            .as_deref()
                            .ok_or(DbError::Corrupt("rename event without a destination"))?;
                        Self::apply_own_rename(
                            &tx,
                            event.seq,
                            *ino,
                            old_path,
                            new_path,
                            *mtime_ns,
                        )?;
                    }
                    EventPayload::Link { ino, mtime_ns } => {
                        let path = event
                            .path2
                            .as_deref()
                            .or(event.path.as_deref())
                            .ok_or(DbError::Corrupt("link event without a path"))?;
                        Self::apply_own_link(&tx, event.seq, *ino, path, *mtime_ns)?;
                    }
                    _ => {}
                }
            } else {
                Self::apply_payload(&tx, event)?;
            }
            applied = event.seq;
            outcomes.push(ApplyOutcome::Applied);
        }

        tx.set_meta_i64(keys::APPLIED_SEQ, applied)?;
        tx.set_meta_i64(keys::EPOCH, current_epoch)?;
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
        Ok(BatchReport {
            outcomes,
            applied_seq: applied,
            rejected,
        })
    }

    /// Apply one event's payload inside an open batch transaction.
    fn apply_payload(tx: &WriteTx<'_>, event: &RemoteEvent) -> Result<(), DbError> {
        let seq = event.seq;
        let path = event.path.as_deref();
        let path2 = event.path2.as_deref();
        let data = event.data.as_deref();
        match &event.payload {
            EventPayload::CreateFile { .. }
            | EventPayload::CreateDir { .. }
            | EventPayload::Symlink { .. } => {
                let path = path.ok_or(DbError::Corrupt("create event without a path"))?;
                Self::apply_create(tx, seq, &event.payload, path)?;
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
                    tx, seq, *ino, *offset, *size, *file_root, *mtime_ns, chunks, data, path,
                )?;
            }
            EventPayload::Truncate {
                ino,
                size,
                file_root,
                mtime_ns,
            } => {
                Self::apply_truncate(tx, seq, *ino, *size, *file_root, *mtime_ns, path)?;
            }
            EventPayload::Setattr {
                ino,
                mode,
                uid,
                gid,
                mtime_ns,
                size,
            } => {
                if let Some(size) = size {
                    Self::apply_truncate(
                        tx,
                        seq,
                        *ino,
                        *size,
                        [0u8; 32],
                        mtime_ns.unwrap_or(0),
                        path,
                    )?;
                }
                if !Self::apply_setattr_attrs(tx, seq, *ino, mode, uid, gid, mtime_ns)?
                    && size.is_none()
                {
                    Self::note_skip(tx, seq, "setattr", *ino, path, "object is gone")?;
                }
            }
            EventPayload::Rename { ino, mtime_ns } => {
                let old_path = path.ok_or(DbError::Corrupt("rename event without a path"))?;
                let new_path =
                    path2.ok_or(DbError::Corrupt("rename event without a destination"))?;
                Self::apply_rename(tx, seq, *ino, old_path, new_path, *mtime_ns)?;
            }
            EventPayload::Unlink { ino, mtime_ns } => {
                let path = path.ok_or(DbError::Corrupt("unlink event without a path"))?;
                Self::apply_remove(tx, seq, *ino, path, false, *mtime_ns)?;
            }
            EventPayload::Rmdir { ino, mtime_ns } => {
                let path = path.ok_or(DbError::Corrupt("rmdir event without a path"))?;
                Self::apply_remove(tx, seq, *ino, path, true, *mtime_ns)?;
            }
            EventPayload::Link { ino, mtime_ns } => {
                let path = path2
                    .or(path)
                    .ok_or(DbError::Corrupt("link event without a path"))?;
                Self::apply_link(tx, seq, *ino, path, *mtime_ns)?;
            }
            EventPayload::Lock { .. }
            | EventPayload::Unlock { .. }
            | EventPayload::Leave
            | EventPayload::SyncCtrl { .. } => {
                // Advisory locks and control markers have no durable object
                // effect in this client.
            }
        }
        Ok(())
    }

    /// Delete an outbox row (and any coalesced members stored in `undo`).
    /// Returns the chunk hashes whose refcount must be refreshed.
    fn ack_outbox(
        tx: &WriteTx<'_>,
        op_id: [u8; 16],
    ) -> Result<Option<Vec<[u8; 32]>>, DbError> {
        let exists: bool = tx.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM outbox WHERE op_id = ?1)",
            [op_id.as_slice()],
            |row| row.get(0),
        )?;
        if !exists {
            return Ok(None);
        }
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
        Ok(Some(hashes))
    }

    fn apply_create(
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
        // The parent may be gone when the client applied a later deletion of
        // the whole subtree first. There is nowhere to attach the name, so
        // skip; the server's own later events settle the object.
        let Some(parent) = Self::live_dir_in(tx, parent_path)? else {
            Self::note_skip(tx, seq, "create", ino, Some(path), "parent directory is gone")?;
            return Ok(());
        };

        let existing = Self::name_in_read(tx, parent, name)?;
        if let Some(existing_ino) = existing {
            if existing_ino != ino {
                // The server's order is authoritative: detach the losing
                // local entry, then link the winner.
                Self::detach_name(tx, parent, name, existing_ino, seq)?;
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
        // The server stamps the parent with the create's timestamp. A
        // fast-forwarding replica never sees a synthetic `setattr`, so the
        // live create event must carry this change itself.
        touch_object(tx, parent, mtime_ns, seq)?;
        Self::next_fuse_ino(tx, ino)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_write(
        tx: &WriteTx<'_>,
        seq: i64,
        ino: Ino,
        offset: u64,
        size: u64,
        file_root: [u8; 32],
        mtime_ns: i64,
        chunks: &[ChunkRef],
        data: Option<&[u8]>,
        path: Option<&str>,
    ) -> Result<(), DbError> {
        // A missing or tombstoned object means the client already applied a
        // later deletion of this inode. The write has no home; skip it.
        let Some(mut object) = Self::object_in(tx, ino)?.filter(|object| !object.deleted) else {
            Self::note_skip(tx, seq, "write", ino, path, "object is gone")?;
            return Ok(());
        };
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
                    // The stream did not arrive and the chunk is not in the
                    // local store. Advancing `applied_seq` here would make
                    // the file permanently unreadable: a reconnect resumes
                    // after this event and never asks for its content again.
                    // Fail the transaction instead; the reconnect replays
                    // this sequence with the server's content.
                    if Self::chunk_data_in(tx, chunk.hash)?.is_none() {
                        return Err(DbError::MissingChunk(chunk.hash));
                    }
                    ChunkRef {
                        chunk_no: chunk.chunk_no,
                        hash: chunk.hash,
                        offset: chunk.offset,
                        len: chunk.len,
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
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_truncate(
        tx: &WriteTx<'_>,
        seq: i64,
        ino: Ino,
        size: u64,
        file_root: [u8; 32],
        mtime_ns: i64,
        path: Option<&str>,
    ) -> Result<(), DbError> {
        let Some(mut object) = Self::object_in(tx, ino)?.filter(|object| !object.deleted) else {
            Self::note_skip(tx, seq, "truncate", ino, path, "object is gone")?;
            return Ok(());
        };
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
                let chunk = tx
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

    /// Apply the metadata half of a `setattr` event.
    ///
    /// Returns `false` when the object is gone; the caller decides whether
    /// that is a normal echo or a skip worth recording.
    fn apply_setattr_attrs(
        tx: &WriteTx<'_>,
        seq: i64,
        ino: Ino,
        mode: &Option<u32>,
        uid: &Option<u32>,
        gid: &Option<u32>,
        mtime_ns: &Option<i64>,
    ) -> Result<bool, DbError> {
        let Some(mut object) = Self::object_in(tx, ino)?.filter(|object| !object.deleted) else {
            return Ok(false);
        };
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
        Ok(true)
    }

    fn apply_rename(
        tx: &WriteTx<'_>,
        seq: i64,
        ino: Ino,
        old_path: &str,
        new_path: &str,
        mtime_ns: Option<i64>,
    ) -> Result<(), DbError> {
        let (old_parent_path, old_name) =
            split_path(old_path).ok_or(DbError::Corrupt("rename of the root"))?;
        let (new_parent_path, new_name) =
            split_path(new_path).ok_or(DbError::Corrupt("rename to the root"))?;
        // Any missing end means the client already applied a later deletion.
        // The rename has nothing left to move; skip it.
        let Some(object) = Self::object_in(tx, ino)?.filter(|object| !object.deleted) else {
            Self::note_skip(tx, seq, "rename", ino, Some(old_path), "object is gone")?;
            return Ok(());
        };
        let Some(old_parent) = Self::live_dir_in(tx, old_parent_path)? else {
            Self::note_skip(tx, seq, "rename", ino, Some(old_path), "source parent is gone")?;
            return Ok(());
        };
        let Some(new_parent) = Self::live_dir_in(tx, new_parent_path)? else {
            Self::note_skip(tx, seq, "rename", ino, Some(old_path), "destination parent is gone")?;
            return Ok(());
        };
        // The server stamps the moved object and both parents, whether or not
        // the names still match the local tree. Apply that metadata first.
        if let Some(mtime_ns) = mtime_ns {
            touch_object(tx, ino, mtime_ns, seq)?;
            touch_object(tx, old_parent, mtime_ns, seq)?;
            if old_parent != new_parent {
                touch_object(tx, new_parent, mtime_ns, seq)?;
            }
        }
        let old_entry = Self::name_in_tx(tx, old_parent, old_name)?;
        let new_entry = Self::name_in_tx(tx, new_parent, new_name)?;
        let Some(source) = old_entry else {
            // The local rename (or its echo) already moved the name.
            Self::note_echo(seq, "rename", ino, Some(old_path), "source name is gone");
            return Ok(());
        };
        if source != ino {
            // The source name now belongs to another object; the server's
            // rename does not describe this tree. Leave it alone.
            Self::note_echo(
                seq,
                "rename",
                ino,
                Some(old_path),
                "source name holds another object",
            );
            return Ok(());
        }
        if let Some(target) = new_entry {
            if target != ino {
                Self::detach_name(tx, new_parent, new_name, target, seq)?;
            }
        }
        tx.delete_name(old_parent, old_name)?;
        if object.kind.is_dir() {
            Self::rewrite_subtree_paths(tx, old_path, new_path)?;
            if old_parent != new_parent {
                bump_nlink(tx, old_parent, -1)?;
                bump_nlink(tx, new_parent, 1)?;
            }
        }
        if Self::name_in_tx(tx, new_parent, new_name)?.is_none() {
            tx.put_name(new_parent, new_name, ino, new_path)?;
        }
        Self::next_fuse_ino(tx, ino)?;
        Ok(())
    }

    /// Apply the server's effect of our own rename echo.
    ///
    /// The local rename was optimistic. The server resolves both paths, so
    /// its event can name a different inode than the one this client moved
    /// (another client created the source name first). The event is the
    /// authority: the destination must name the event inode, and a stale
    /// local winner must lose the name.
    fn apply_own_rename(
        tx: &WriteTx<'_>,
        seq: i64,
        ino: Ino,
        old_path: &str,
        new_path: &str,
        mtime_ns: Option<i64>,
    ) -> Result<(), DbError> {
        if old_path == new_path {
            return Ok(());
        }
        let (old_parent_path, old_name) =
            split_path(old_path).ok_or(DbError::Corrupt("rename of the root"))?;
        let (new_parent_path, new_name) =
            split_path(new_path).ok_or(DbError::Corrupt("rename to the root"))?;
        let Some(object) = Self::object_in(tx, ino)?.filter(|object| !object.deleted) else {
            Self::note_skip(tx, seq, "rename", ino, Some(old_path), "object is gone")?;
            return Ok(());
        };
        let Some(new_parent) = Self::live_dir_in(tx, new_parent_path)? else {
            Self::note_skip(
                tx,
                seq,
                "rename",
                ino,
                Some(old_path),
                "destination parent is gone",
            )?;
            return Ok(());
        };
        let old_parent = Self::live_dir_in(tx, old_parent_path)?;
        if let Some(mtime_ns) = mtime_ns {
            touch_object(tx, ino, mtime_ns, seq)?;
            if let Some(parent) = old_parent {
                touch_object(tx, parent, mtime_ns, seq)?;
            }
            if old_parent != Some(new_parent) {
                touch_object(tx, new_parent, mtime_ns, seq)?;
            }
        }

        // Drop the source name when it still names the event inode. The
        // optimistic local rename usually removed it already.
        let source_present = match old_parent {
            Some(parent) => Self::name_in_tx(tx, parent, old_name)? == Some(ino),
            None => false,
        };
        if source_present {
            let parent = old_parent.ok_or(DbError::Corrupt("source parent vanished"))?;
            tx.delete_name(parent, old_name)?;
            if !object.kind.is_dir() {
                bump_nlink(tx, ino, -1)?;
            } else if parent != new_parent {
                bump_nlink(tx, parent, -1)?;
            }
        }

        // Make the destination name the event inode.
        match Self::name_in_tx(tx, new_parent, new_name)? {
            Some(existing) if existing == ino => {}
            Some(existing) => {
                Self::detach_name(tx, new_parent, new_name, existing, seq)?;
                tx.put_name(new_parent, new_name, ino, new_path)?;
                if !object.kind.is_dir() {
                    bump_nlink(tx, ino, 1)?;
                } else {
                    bump_nlink(tx, new_parent, 1)?;
                }
            }
            None => {
                tx.put_name(new_parent, new_name, ino, new_path)?;
                if !object.kind.is_dir() {
                    bump_nlink(tx, ino, 1)?;
                } else {
                    bump_nlink(tx, new_parent, 1)?;
                }
            }
        }

        if object.kind.is_dir() && source_present {
            Self::rewrite_subtree_paths(tx, old_path, new_path)?;
        }
        Self::next_fuse_ino(tx, ino)?;
        Ok(())
    }

    /// Apply the server's effect of our own link echo.
    ///
    /// The local link already created the name when the inode matches. When
    /// the server resolved the target to another inode, replace the local
    /// winner so both replicas name the same object.
    fn apply_own_link(
        tx: &WriteTx<'_>,
        seq: i64,
        ino: Ino,
        path: &str,
        mtime_ns: Option<i64>,
    ) -> Result<(), DbError> {
        let (parent_path, name) =
            split_path(path).ok_or(DbError::Corrupt("link at the root"))?;
        let Some(parent) = Self::live_dir_in(tx, parent_path)? else {
            Self::note_skip(tx, seq, "link", ino, Some(path), "parent directory is gone")?;
            return Ok(());
        };
        let Some(object) = Self::object_in(tx, ino)?.filter(|object| !object.deleted) else {
            Self::note_skip(tx, seq, "link", ino, Some(path), "object is gone")?;
            return Ok(());
        };
        if let Some(mtime_ns) = mtime_ns {
            touch_object(tx, parent, mtime_ns, seq)?;
        }
        match Self::name_in_tx(tx, parent, name)? {
            Some(existing) if existing == ino => {
                Self::note_echo(seq, "link", ino, Some(path), "name already exists");
            }
            Some(existing) => {
                Self::detach_name(tx, parent, name, existing, seq)?;
                tx.put_name(parent, name, ino, path)?;
                if !object.kind.is_dir() {
                    bump_nlink(tx, ino, 1)?;
                }
                Self::next_fuse_ino(tx, ino)?;
            }
            None => {
                tx.put_name(parent, name, ino, path)?;
                if !object.kind.is_dir() {
                    bump_nlink(tx, ino, 1)?;
                }
                Self::next_fuse_ino(tx, ino)?;
            }
        }
        Ok(())
    }

    fn apply_remove(
        tx: &WriteTx<'_>,
        seq: i64,
        ino: Ino,
        path: &str,
        is_dir: bool,
        mtime_ns: Option<i64>,
    ) -> Result<(), DbError> {
        let (parent_path, name) =
            split_path(path).ok_or(DbError::Corrupt("unlink of the root"))?;
        let Some(parent) = Self::live_dir_in(tx, parent_path)? else {
            // The client applied a later deletion of the parent first. Drop a
            // name row left behind by an earlier directory conflict so the
            // path cannot resurrect, then skip.
            Self::drop_unreachable_name(tx, seq, path)?;
            Self::settle_removed(tx, seq, ino, is_dir, mtime_ns)?;
            Self::note_skip(tx, seq, "remove", ino, Some(path), "parent directory is gone")?;
            return Ok(());
        };
        if let Some(mtime_ns) = mtime_ns {
            touch_object(tx, parent, mtime_ns, seq)?;
        }
        match Self::name_in_tx(tx, parent, name)? {
            None => {
                // The local removal (or its echo) already deleted the name.
                Self::settle_removed(tx, seq, ino, is_dir, mtime_ns)?;
                Self::note_echo(seq, "remove", ino, Some(path), "name is gone");
                return Ok(());
            }
            Some(existing) if existing != ino => {
                // A later local create or rename owns the name now. Server
                // order wins: the local winner loses the name and its pending
                // outbox rows recreate it afterwards.
                Self::detach_name(tx, parent, name, existing, seq)?;
                Self::settle_removed(tx, seq, ino, is_dir, mtime_ns)?;
                Self::note_skip(
                    tx,
                    seq,
                    "remove",
                    ino,
                    Some(path),
                    "name is held by another object",
                )?;
                return Ok(());
            }
            Some(_) => {}
        }
        tx.delete_name(parent, name)?;
        let Some(object) = Self::object_in(tx, ino)? else {
            // The client never held this object (an earlier create was
            // overtaken by a later deletion). Keep the server's tombstone so
            // the object tables stay aligned.
            if is_dir {
                bump_nlink(tx, parent, -1)?;
            }
            return Self::put_tombstone(tx, seq, ino, is_dir, mtime_ns);
        };
        if object.kind.is_dir() {
            bump_nlink(tx, parent, -1)?;
        }
        Self::tombstone_removed(tx, seq, object)
    }

    fn apply_link(
        tx: &WriteTx<'_>,
        seq: i64,
        ino: Ino,
        path: &str,
        mtime_ns: Option<i64>,
    ) -> Result<(), DbError> {
        let (parent_path, name) =
            split_path(path).ok_or(DbError::Corrupt("link at the root"))?;
        let Some(parent) = Self::live_dir_in(tx, parent_path)? else {
            Self::note_skip(tx, seq, "link", ino, Some(path), "parent directory is gone")?;
            return Ok(());
        };
        if let Some(mtime_ns) = mtime_ns {
            touch_object(tx, parent, mtime_ns, seq)?;
        }
        if Self::name_in_tx(tx, parent, name)?.is_some() {
            // The local link (or its echo) already created the name.
            Self::note_echo(seq, "link", ino, Some(path), "name already exists");
            return Ok(());
        }
        let Some(mut object) = Self::object_in(tx, ino)?.filter(|object| !object.deleted) else {
            Self::note_skip(tx, seq, "link", ino, Some(path), "object is gone")?;
            return Ok(());
        };
        object.nlink = object.nlink.saturating_add(1);
        object.updated_seq = seq;
        tx.put_object(&object)?;
        tx.put_name(parent, name, ino, path)?;
        Self::next_fuse_ino(tx, ino)?;
        Ok(())
    }

    /// Detach a losing name and tombstone its object when the last link goes.
    fn detach_name(
        tx: &WriteTx<'_>,
        parent: Ino,
        name: &str,
        ino: Ino,
        seq: i64,
    ) -> Result<(), DbError> {
        tx.delete_name(parent, name)?;
        let Some(mut object) = Self::object_in(tx, ino)? else {
            // The name referenced an inode this replica never held. Leave the
            // server's tombstone behind so the object table stays aligned.
            return Self::put_tombstone(tx, seq, ino, false, None);
        };
        if object.kind.is_dir() {
            bump_nlink(tx, parent, -1)?;
            return Self::tombstone_subtree(tx, seq, ino);
        }
        object.nlink = object.nlink.saturating_sub(1);
        if object.nlink == 0 {
            tx.set_object_chunks(ino, &[])?;
            object.deleted = true;
            object.nlink = 0;
        }
        object.updated_seq = seq;
        tx.put_object(&object)?;
        Ok(())
    }

    /// Remove an object whose name is already gone.
    ///
    /// A live row with no name is the signature of a directory removal that
    /// decremented `nlink` instead of dropping the directory. The server keeps
    /// a tombstone, so the replica does too.
    fn settle_removed(
        tx: &WriteTx<'_>,
        seq: i64,
        ino: Ino,
        is_dir: bool,
        mtime_ns: Option<i64>,
    ) -> Result<(), DbError> {
        let Some(object) = Self::object_in(tx, ino)? else {
            return Self::put_tombstone(tx, seq, ino, is_dir, mtime_ns);
        };
        if object.deleted {
            return Ok(());
        }
        let names: i64 = tx.conn().query_row(
            "SELECT COUNT(*) FROM names WHERE ino = ?1",
            [ino.as_slice()],
            |row| row.get(0),
        )?;
        if names == 0 {
            if object.kind.is_dir() {
                return Self::tombstone_subtree(tx, seq, object.ino);
            }
            return Self::tombstone_now(tx, seq, object);
        }
        Ok(())
    }

    /// Drop one object outright, regardless of its recorded link count.
    fn tombstone_now(tx: &WriteTx<'_>, seq: i64, object: Object) -> Result<(), DbError> {
        tx.set_object_chunks(object.ino, &[])?;
        let mut updated = object;
        updated.deleted = true;
        updated.nlink = 0;
        updated.updated_seq = seq;
        tx.put_object(&updated)?;
        Ok(())
    }

    /// Tombstone one object and, for a directory, its remaining subtree.
    fn tombstone_removed(tx: &WriteTx<'_>, seq: i64, object: Object) -> Result<(), DbError> {
        if object.kind.is_dir() {
            return Self::tombstone_subtree(tx, seq, object.ino);
        }
        let mut updated = object;
        updated.nlink = updated.nlink.saturating_sub(1);
        if updated.nlink == 0 {
            tx.set_object_chunks(updated.ino, &[])?;
            updated.deleted = true;
            updated.nlink = 0;
        }
        updated.updated_seq = seq;
        tx.put_object(&updated)?;
        Ok(())
    }

    /// Tombstone a directory and every child name it still holds.
    ///
    /// Server order removes a directory's children before the directory. A
    /// child that remains here is local intent the server never accepted; the
    /// outbox recreates it after the replay, so dropping the speculative rows
    /// keeps the replicated tree equal to the server's.
    fn tombstone_subtree(tx: &WriteTx<'_>, seq: i64, ino: Ino) -> Result<(), DbError> {
        let mut children = Vec::new();
        {
            let mut stmt = tx
                .conn()
                .prepare("SELECT name, ino FROM names WHERE parent = ?1 ORDER BY name")?;
            let mut rows = stmt.query([ino.as_slice()])?;
            while let Some(row) = rows.next()? {
                let name: String = row.get(0)?;
                let child: Vec<u8> = row.get(1)?;
                let child: Ino = child
                    .try_into()
                    .map_err(|_| DbError::Corrupt("names.ino is not 16 bytes"))?;
                children.push((name, child));
            }
        }
        for (name, child) in children {
            tx.delete_name(ino, &name)?;
            if let Some(object) = Self::object_in(tx, child)? {
                Self::tombstone_removed(tx, seq, object)?;
            }
        }
        let Some(mut object) = Self::object_in(tx, ino)? else {
            return Ok(());
        };
        tx.set_object_chunks(ino, &[])?;
        object.deleted = true;
        object.nlink = 0;
        object.updated_seq = seq;
        tx.put_object(&object)?;
        Ok(())
    }

    /// Leave a tombstone for an inode this replica never held.
    ///
    /// The attributes are unknown; a tombstone is never visible through the
    /// mount, and its only job is to keep the object table aligned with the
    /// server's deleted row.
    fn put_tombstone(
        tx: &WriteTx<'_>,
        seq: i64,
        ino: Ino,
        is_dir: bool,
        mtime_ns: Option<i64>,
    ) -> Result<(), DbError> {
        if Self::object_in(tx, ino)?.is_some() {
            return Ok(());
        }
        let kind = if is_dir {
            ObjectKind::Dir
        } else {
            ObjectKind::File
        };
        let object = Object {
            ino,
            kind,
            mode: if is_dir { 0o755 } else { 0o644 },
            uid: 0,
            gid: 0,
            mtime_ns: mtime_ns.unwrap_or(0),
            size: 0,
            file_root: crate::store::sqlite::file_root(kind, None, &[]),
            block_count: 0,
            target: None,
            nlink: 0,
            deleted: true,
            created_seq: seq,
            updated_seq: seq,
        };
        tx.put_object(&object)?;
        Ok(())
    }

    /// Delete the name row at `path` when its parent directory is no longer
    /// reachable.
    ///
    /// A directory that lost a create conflict keeps its children: the server
    /// only detaches the directory's own name. The rows stay reachable by
    /// `path`, so a later removal of the parent would otherwise leave them
    /// behind for good.
    fn drop_unreachable_name(
        tx: &WriteTx<'_>,
        seq: i64,
        path: &str,
    ) -> Result<(), DbError> {
        let Some((_, name)) = split_path(path) else {
            return Ok(());
        };
        let row: Option<(Vec<u8>, Vec<u8>)> = tx
            .conn()
            .query_row("SELECT parent, ino FROM names WHERE path = ?1", [path], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()?;
        let Some((parent, ino)) = row else {
            return Ok(());
        };
        let parent: Ino = parent
            .try_into()
            .map_err(|_| DbError::Corrupt("names.parent is not 16 bytes"))?;
        let ino: Ino = ino
            .try_into()
            .map_err(|_| DbError::Corrupt("names.ino is not 16 bytes"))?;
        Self::detach_name(tx, parent, name, ino, seq)
    }

    /// Log and count an event the local tree has already overtaken.
    fn note_skip(
        tx: &WriteTx<'_>,
        seq: i64,
        kind: &'static str,
        ino: Ino,
        path: Option<&str>,
        reason: &'static str,
    ) -> Result<(), DbError> {
        tracing::warn!(
            event = "replay_skip",
            seq,
            kind,
            ino = ?ino,
            path = ?path,
            reason,
            "skipping an event the local tree has already overtaken"
        );
        let skipped: i64 = tx
            .conn()
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [META_REPLAY_SKIPPED],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        tx.set_meta_i64(META_REPLAY_SKIPPED, skipped.saturating_add(1))?;
        Ok(())
    }

    /// Record a no-op that is the expected echo of a local operation.
    fn note_echo(seq: i64, kind: &'static str, ino: Ino, path: Option<&str>, reason: &'static str) {
        tracing::debug!(
            event = "replay_noop",
            seq,
            kind,
            ino = ?ino,
            path = ?path,
            reason,
            "the local tree already holds the event's effect"
        );
    }

    /// Resolve a path to a live directory, treating anything missing or
    /// tombstoned as `None`.
    fn live_dir_in(tx: &WriteTx<'_>, path: &str) -> Result<Option<Ino>, DbError> {
        let Some(ino) = Self::ino_by_path_opt_in(tx, path)? else {
            return Ok(None);
        };
        match Self::object_in(tx, ino)? {
            Some(object) if !object.deleted && object.kind.is_dir() => Ok(Some(ino)),
            _ => Ok(None),
        }
    }

    /// Resolve a path to an inode without failing when the entry is gone.
    fn ino_by_path_opt_in(tx: &WriteTx<'_>, path: &str) -> Result<Option<Ino>, DbError> {
        match Self::ino_by_path_in(tx, path) {
            Ok(ino) => Ok(Some(ino)),
            Err(DbError::Errno(Errno::ENOENT)) => Ok(None),
            Err(error) => Err(error),
        }
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

    fn name_in_read(tx: &WriteTx<'_>, parent: Ino, name: &str) -> Result<Option<Ino>, DbError> {
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

    /// Adopt a compacted server epoch without clearing the replicated tree.
    ///
    /// The caller has established that the local tree already equals the
    /// state the compacted log describes: `applied` is the last sequence of
    /// that log and `epoch` the epoch that carries it. Buffered writes are
    /// committed first; they are local intent, and the new watermark must sit
    /// above the tree those writes produced.
    pub fn fast_forward(&self, epoch: i64, applied: i64) -> Result<(), DbError> {
        self.flush_all()?;
        self.write(|tx| {
            tx.set_meta_i64(keys::EPOCH, epoch)?;
            tx.set_meta_i64(keys::APPLIED_SEQ, applied)?;
            tx.set_meta_i64(keys::COVERED_SEQ, applied)?;
            tx.set_meta_i64(keys::LAST_CHECKPOINT_AT, now_ns() / 1_000_000_000)?;
            // The local event cache describes the old epoch; sequence numbers
            // restart at zero, so those rows no longer name this history.
            tx.conn().execute("DELETE FROM events", [])?;
            let pending: i64 = tx.conn().query_row(
                "SELECT COUNT(*) FROM outbox WHERE state IN ('pending', 'sent')",
                [],
                |row| row.get(0),
            )?;
            tx.set_meta_i64(keys::DIRTY, i64::from(pending != 0))?;
            Ok(())
        })
    }

    /// Report every broken object/name invariant in the replicated tree.
    ///
    /// The check reads only local rows. A clean report means the tree is
    /// addressable and its link counts agree with its names; it does not
    /// compare attributes with the server, which only a replay can settle.
    pub fn check_replica(&self) -> Result<Vec<ReplicaIssue>, DbError> {
        let tx = self.read()?;
        Self::check_replica_rows(tx.conn())
    }

    fn check_replica_rows(
        conn: &rusqlite::Connection,
    ) -> Result<Vec<ReplicaIssue>, DbError> {
        let (objects, names) = Self::replica_rows(conn)?;
        let mut issues = Vec::new();
        if !objects
            .get(&ROOT_INO)
            .is_some_and(|root| !root.deleted && root.kind.is_dir())
        {
            issues.push(ReplicaIssue::RootMissing);
        }

        let mut name_count: BTreeMap<Ino, u32> = BTreeMap::new();
        let mut child_dirs: BTreeMap<Ino, u32> = BTreeMap::new();
        for name in &names {
            *name_count.entry(name.ino).or_default() += 1;
            if objects
                .get(&name.ino)
                .is_some_and(|object| !object.deleted && object.kind.is_dir())
            {
                *child_dirs.entry(name.parent).or_default() += 1;
            }
        }

        for (ino, object) in &objects {
            if object.deleted {
                if object.nlink != 0 {
                    issues.push(ReplicaIssue::DeletedObjectWithLinks {
                        ino: *ino,
                        nlink: object.nlink,
                    });
                }
                continue;
            }
            if *ino != ROOT_INO && name_count.get(ino).copied().unwrap_or(0) == 0 {
                issues.push(ReplicaIssue::LiveObjectWithoutName { ino: *ino });
            }
            let expected = if object.kind.is_dir() {
                2 + child_dirs.get(ino).copied().unwrap_or(0)
            } else {
                name_count.get(ino).copied().unwrap_or(0)
            };
            if object.nlink != expected {
                issues.push(ReplicaIssue::NlinkMismatch {
                    ino: *ino,
                    found: object.nlink,
                    expected,
                });
            }
        }

        for name in &names {
            let parent_ok = objects
                .get(&name.parent)
                .is_some_and(|parent| !parent.deleted && parent.kind.is_dir());
            if !parent_ok {
                issues.push(ReplicaIssue::NameUnderMissingParent {
                    path: name.path.clone(),
                });
            }
            match objects.get(&name.ino) {
                None => issues.push(ReplicaIssue::NameToMissingObject {
                    path: name.path.clone(),
                }),
                Some(_) if name.ino == ROOT_INO => {
                    issues.push(ReplicaIssue::RootHasName {
                        path: name.path.clone(),
                    });
                }
                Some(object) if object.deleted => {
                    issues.push(ReplicaIssue::NameToDeletedObject {
                        path: name.path.clone(),
                    });
                    issues.push(ReplicaIssue::DeletedObjectWithName {
                        ino: name.ino,
                        path: name.path.clone(),
                    });
                }
                Some(_) => {}
            }
        }

        Self::check_replica_paths(&objects, &names, &mut issues);
        Ok(issues)
    }

    fn check_replica_paths(
        objects: &BTreeMap<Ino, Object>,
        names: &[ReplicaName],
        issues: &mut Vec<ReplicaIssue>,
    ) {
        let mut by_parent: BTreeMap<Ino, Vec<&ReplicaName>> = BTreeMap::new();
        for name in names {
            by_parent.entry(name.parent).or_default().push(name);
        }
        let mut stack = vec![(ROOT_INO, "/".to_owned())];
        let mut visited = BTreeMap::new();
        visited.insert(ROOT_INO, ());
        while let Some((parent, parent_path)) = stack.pop() {
            let Some(children) = by_parent.get(&parent) else {
                continue;
            };
            for name in children {
                let expected = if parent_path == "/" {
                    format!("/{}", name.name)
                } else {
                    format!("{parent_path}/{}", name.name)
                };
                if name.path != expected {
                    issues.push(ReplicaIssue::PathMismatch {
                        stored: name.path.clone(),
                        expected: expected.clone(),
                    });
                }
                if objects
                    .get(&name.ino)
                    .is_some_and(|object| !object.deleted && object.kind.is_dir())
                    && visited.insert(name.ino, ()).is_none()
                {
                    stack.push((name.ino, expected));
                }
            }
        }
    }

    /// Repair the object/name invariants without changing the visible tree.
    ///
    /// The repair only touches rows that are already invisible: nameless live
    /// objects become tombstones, tombstones lose their stale links and names,
    /// dangling names disappear, and the denormalized `names.path` is rebuilt
    /// from the parent chain. It never adds or renames a visible entry.
    pub fn repair_replica_metadata(&self) -> Result<ReplicaRepair, DbError> {
        // A clean replica needs no write transaction at all. The check and
        // the repair both run before the write gate and the write-back
        // thread, so no local writer can slip between them.
        let issues = self.check_replica()?;
        if issues.is_empty() {
            return Ok(ReplicaRepair::default());
        }
        self.write(|tx| {
            let mut report = ReplicaRepair {
                issues: issues.len() as u64,
                ..ReplicaRepair::default()
            };
            let (mut objects, mut names) = Self::replica_rows(tx.conn())?;

            if !objects
                .get(&ROOT_INO)
                .is_some_and(|root| !root.deleted && root.kind.is_dir())
            {
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
                objects.insert(ROOT_INO, root);
                report.roots += 1;
            }

            // Tombstoning a nameless directory orphans its children, and
            // tombstoning those can orphan theirs. Repeat until the tree
            // stops changing; every round removes at least one row.
            loop {
                let mut kept = Vec::with_capacity(names.len());
                for name in names.drain(..) {
                    let parent_ok = objects
                        .get(&name.parent)
                        .is_some_and(|parent| !parent.deleted && parent.kind.is_dir());
                    let ino_ok = name.ino != ROOT_INO
                        && objects
                            .get(&name.ino)
                            .is_some_and(|object| !object.deleted);
                    if parent_ok && ino_ok {
                        kept.push(name);
                    } else {
                        tx.delete_name(name.parent, &name.name)?;
                        report.names_removed += 1;
                    }
                }
                names = kept;

                let mut name_count: BTreeMap<Ino, u32> = BTreeMap::new();
                for name in &names {
                    *name_count.entry(name.ino).or_default() += 1;
                }
                let nameless: Vec<Ino> = objects
                    .iter()
                    .filter(|(ino, object)| {
                        **ino != ROOT_INO
                            && !object.deleted
                            && name_count.get(*ino).copied().unwrap_or(0) == 0
                    })
                    .map(|(ino, _)| *ino)
                    .collect();
                if nameless.is_empty() {
                    break;
                }
                for ino in nameless {
                    if let Some(mut object) = objects.remove(&ino) {
                        tx.set_object_chunks(ino, &[])?;
                        object.deleted = true;
                        object.nlink = 0;
                        tx.put_object(&object)?;
                        report.tombstones += 1;
                    }
                }
            }

            let mut name_count: BTreeMap<Ino, u32> = BTreeMap::new();
            let mut child_dirs: BTreeMap<Ino, u32> = BTreeMap::new();
            for name in &names {
                *name_count.entry(name.ino).or_default() += 1;
                if objects
                    .get(&name.ino)
                    .is_some_and(|object| !object.deleted && object.kind.is_dir())
                {
                    *child_dirs.entry(name.parent).or_default() += 1;
                }
            }

            for (ino, object) in &mut objects {
                let expected = if object.deleted {
                    0
                } else if object.kind.is_dir() {
                    2 + child_dirs.get(ino).copied().unwrap_or(0)
                } else {
                    name_count.get(ino).copied().unwrap_or(0)
                };
                if object.nlink != expected {
                    object.nlink = expected;
                    tx.put_object(object)?;
                    report.nlinks += 1;
                }
            }

            for (parent, name, path) in Self::replica_path_updates(&objects, &names) {
                tx.conn().execute(
                    "UPDATE names SET path = ?1 WHERE parent = ?2 AND name = ?3",
                    params![path, parent.as_slice(), name],
                )?;
                report.paths += 1;
            }
            Ok(report)
        })
    }

    fn replica_path_updates(
        objects: &BTreeMap<Ino, Object>,
        names: &[ReplicaName],
    ) -> Vec<(Ino, String, String)> {
        let mut by_parent: BTreeMap<Ino, Vec<&ReplicaName>> = BTreeMap::new();
        for name in names {
            by_parent.entry(name.parent).or_default().push(name);
        }
        let mut updates = Vec::new();
        let mut stack = vec![(ROOT_INO, "/".to_owned())];
        let mut visited = BTreeMap::new();
        visited.insert(ROOT_INO, ());
        while let Some((parent, parent_path)) = stack.pop() {
            let Some(children) = by_parent.get(&parent) else {
                continue;
            };
            for name in children {
                let expected = if parent_path == "/" {
                    format!("/{}", name.name)
                } else {
                    format!("{parent_path}/{}", name.name)
                };
                if name.path != expected {
                    updates.push((name.parent, name.name.clone(), expected.clone()));
                }
                if objects
                    .get(&name.ino)
                    .is_some_and(|object| !object.deleted && object.kind.is_dir())
                    && visited.insert(name.ino, ()).is_none()
                {
                    stack.push((name.ino, expected));
                }
            }
        }
        updates
    }

    fn replica_rows(
        conn: &rusqlite::Connection,
    ) -> Result<(BTreeMap<Ino, Object>, Vec<ReplicaName>), DbError> {
        let mut objects = BTreeMap::new();
        {
            let mut stmt = conn.prepare(
                "SELECT ino, kind, mode, uid, gid, mtime_ns, size, file_root, block_count,
                        target, nlink, deleted, created_seq, updated_seq
                   FROM objects",
            )?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let object = super::db::object_from_row_offset(row, 0)?;
                objects.insert(object.ino, object);
            }
        }
        let mut names = Vec::new();
        {
            let mut stmt = conn.prepare("SELECT parent, name, ino, path FROM names")?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let parent: Vec<u8> = row.get(0)?;
                let parent: Ino = parent
                    .try_into()
                    .map_err(|_| DbError::Corrupt("names.parent is not 16 bytes"))?;
                let name: String = row.get(1)?;
                let ino: Vec<u8> = row.get(2)?;
                let ino: Ino = ino
                    .try_into()
                    .map_err(|_| DbError::Corrupt("names.ino is not 16 bytes"))?;
                let path: String = row.get(3)?;
                names.push(ReplicaName {
                    parent,
                    name,
                    ino,
                    path,
                });
            }
        }
        Ok((objects, names))
    }

    /// Clear the replicated tables for a new server epoch.
    ///
    /// The outbox survives: those are local intentions that will be resent
    /// after the replay. `applied_seq` restarts at zero.
    pub fn reset_epoch(&self, epoch: i64) -> Result<(), DbError> {
        // Buffered writes are local intent; commit them so they survive the
        // tree reset in the outbox, exactly like a committed write.
        self.flush_all()?;
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
            // A `failed` row is a tombstone: the server never applied it and
            // must not receive it again. Only an in-flight row is retried.
            tx.conn()
                .execute("UPDATE outbox SET state = 'pending' WHERE state = 'sent'", [])?;
            tx.set_meta_i64(super::db::KEY_REPLAY_LOCAL, 1)?;
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
        // The seed walks SQLite; buffered bytes must be part of the tree.
        self.flush_all()?;
        let mut db = self.lock_writer();
        let snapshot = db.read()?;
        let live = collect_live(&snapshot)?;
        let root = snapshot
            .object(ROOT_INO)?
            .ok_or(DbError::Corrupt("root object is missing"))?;
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
                    mtime_ns: Some(item.object.mtime_ns),
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
        // A synthetic create carries the object's current timestamp, but the
        // server's parent update used the original create timestamp. The
        // difference is visible on directories, whose mtime moves with every
        // child. Re-state each directory's attributes after all creates and
        // writes, exactly as compaction does.
        for item in &live {
            if !item.object.kind.is_dir() {
                continue;
            }
            desired.push(SeedRow {
                op_id: seed_op_id("attrs", epoch, &item.path),
                payload: EventPayload::Setattr {
                    ino: item.object.ino,
                    mode: Some(item.object.mode),
                    uid: Some(item.object.uid),
                    gid: Some(item.object.gid),
                    mtime_ns: Some(item.object.mtime_ns),
                    size: None,
                },
                path: item.path.clone(),
                path2: None,
                chunks: Vec::new(),
            });
        }
        // The seed's creates stamp the server's root with each child's
        // timestamp. Send the source root's own attributes last so the server
        // and every replaying replica end on the imported root metadata, not
        // on whichever top-level entry happened to be created last.
        desired.push(SeedRow {
            op_id: seed_op_id("root", epoch, "/"),
            payload: EventPayload::Setattr {
                ino: ROOT_INO,
                mode: Some(root.mode),
                uid: Some(root.uid),
                gid: Some(root.gid),
                mtime_ns: Some(root.mtime_ns),
                size: None,
            },
            path: "/".to_owned(),
            path2: None,
            chunks: Vec::new(),
        });

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
    /// Events skipped because the local tree had already applied a later
    /// deletion. A growing count is a divergence signal, not an error.
    pub fn replay_skipped(&self) -> Result<u64, DbError> {
        let tx = self.read()?;
        let skipped: Option<i64> = tx
            .conn()
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [META_REPLAY_SKIPPED],
                |row| row.get(0),
            )
            .optional()?;
        Ok(u64::try_from(skipped.unwrap_or(0)).unwrap_or(0))
    }

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
    ///
    /// A caller that received only the resync marker passes `None` and
    /// records the replay request itself; a marker never names a path to
    /// replace.
    pub fn reject_op(
        &self,
        op_id: [u8; 16],
        errno: i32,
        state: Option<RejectState>,
    ) -> Result<(), DbError> {
        let updated = self.write(|tx| {
            let updated = tx.conn().execute(
                "UPDATE outbox SET state = 'failed', attempts = MAX(attempts, 1), undo = ?2
                 WHERE op_id = ?1",
                params![op_id.as_slice(), errno.to_le_bytes().to_vec()],
            )?;
            if updated != 0 {
                // A later local operation on the same inode depends on the
                // rejected effect. It must not reach the server and recreate
                // the lost race; the whole chain stays a tombstone.
                tx.conn().execute(
                    "UPDATE outbox
                        SET state = 'failed', attempts = MAX(attempts, 1)
                      WHERE state IN ('pending', 'sent')
                        AND ino IS NOT NULL
                        AND ino = (SELECT ino FROM outbox WHERE op_id = ?1)
                        AND created_at > (SELECT created_at FROM outbox WHERE op_id = ?1)",
                    [op_id.as_slice()],
                )?;
                // The rejection carries the server's authoritative state for
                // the affected path. Replace that path locally; unrelated
                // local work is untouched.
                if let Some(state) = &state {
                    Self::replace_path_in(tx, state)?;
                }
            }
            Ok(updated)
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

    /// Replace one path with the server's authoritative snapshot.
    ///
    /// Only the named path is touched. A missing server object removes the
    /// local name; a present one installs its object, chunk list and name.
    fn replace_path_in(tx: &WriteTx<'_>, state: &RejectState) -> Result<(), DbError> {
        let Some((parent_path, name)) = state.path.rsplit_once('/') else {
            return Ok(());
        };
        let parent_path = if parent_path.is_empty() { "/" } else { parent_path };
        let local_parent: Option<Ino> = if parent_path == "/" {
            Some(ROOT_INO)
        } else {
            tx.conn()
                .query_row(
                    "SELECT ino FROM names WHERE path = ?1",
                    [parent_path],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?
                .and_then(|bytes| bytes.try_into().ok())
        };
        let Some(parent) = local_parent else {
            return Ok(());
        };
        if let Some(existing) = Self::name_in(tx, parent, name)? {
            tx.delete_name(parent, name)?;
            if let Some(mut object) = Self::object_in(tx, existing)? {
                object.nlink = object.nlink.saturating_sub(1);
                if object.nlink == 0 {
                    tx.set_object_chunks(existing, &[])?;
                    object.deleted = true;
                }
                tx.put_object(&object)?;
            }
        }
        if let Some(object) = &state.object {
            for (chunk, bytes) in state.chunks.iter().zip(state.data.iter()) {
                if !bytes.is_empty() {
                    tx.put_chunk(chunk.hash, chunk.len, Some(bytes.as_slice()))?;
                }
            }
            tx.put_object(object)?;
            tx.set_object_chunks(object.ino, &state.chunks)?;
            tx.put_name(parent, name, object.ino, &state.path)?;
            Self::next_fuse_ino(tx, object.ino)?;
        }
        Ok(())
    }

    /// Re-apply the pending outbox effects to the freshly replayed tree.
    ///
    /// A replica reset (epoch change or rejection resync) clears the local
    /// tree and replays the server log. The pending outbox rows are local
    /// intent that the server has not accepted yet; applying them again keeps
    /// unrelated local work visible while the uplink resends it. The rows are
    /// not acknowledged and `applied_seq` does not move.
    pub fn replay_local_outbox(&self) -> Result<usize, DbError> {
        if !self.take_replay_local()? {
            return Ok(0);
        }
        let mut db = self.lock_writer();
        let tx = db.write()?;
        let rows = {
            let mut statement = tx.conn().prepare(
                "SELECT op_id, kind, path, path2, payload, created_at FROM outbox
                  WHERE state IN ('pending', 'sent')
                  ORDER BY created_at",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let mut applied = 0usize;
        for (op_id, kind, path, path2, payload, seq) in rows {
            let op_id: [u8; 16] = op_id
                .try_into()
                .map_err(|_| DbError::Corrupt("outbox op_id is not 16 bytes"))?;
            let kind = EventKind::parse(&kind)
                .ok_or(DbError::Corrupt("unknown outbox kind"))?;
            let payload = EventPayload::decode(kind, &payload)?;
            let data = Self::outbox_data_in(&tx, &op_id)?;
            Self::apply_local_outbox_payload(
                &tx,
                seq,
                &payload,
                path.as_deref(),
                path2.as_deref(),
                data.as_deref(),
            )?;
            applied += 1;
        }
        tx.commit()?;
        Ok(applied)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_local_outbox_payload(
        tx: &WriteTx<'_>,
        seq: i64,
        payload: &EventPayload,
        path: Option<&str>,
        path2: Option<&str>,
        data: Option<&[u8]>,
    ) -> Result<(), DbError> {
        match payload {
            EventPayload::CreateFile { .. }
            | EventPayload::CreateDir { .. }
            | EventPayload::Symlink { .. } => {
                let path = path.ok_or(DbError::Corrupt("create event without a path"))?;
                Self::apply_create(tx, seq, payload, path)?;
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
                    tx, seq, *ino, *offset, *size, *file_root, *mtime_ns, chunks, data, path,
                )?;
            }
            EventPayload::Truncate {
                ino,
                size,
                file_root,
                mtime_ns,
            } => {
                Self::apply_truncate(tx, seq, *ino, *size, *file_root, *mtime_ns, path)?;
            }
            EventPayload::Setattr {
                ino,
                mode,
                uid,
                gid,
                mtime_ns,
                size,
            } => {
                if let Some(size) = size {
                    Self::apply_truncate(
                        tx, seq, *ino, *size, [0u8; 32], mtime_ns.unwrap_or(0), path,
                    )?;
                }
                Self::apply_setattr_attrs(tx, seq, *ino, mode, uid, gid, mtime_ns)?;
            }
            EventPayload::Rename { ino, mtime_ns } => {
                let old_path = path.ok_or(DbError::Corrupt("rename event without a path"))?;
                let new_path =
                    path2.ok_or(DbError::Corrupt("rename event without a destination"))?;
                Self::apply_rename(tx, seq, *ino, old_path, new_path, *mtime_ns)?;
            }
            EventPayload::Unlink { ino, mtime_ns } => {
                let path = path.ok_or(DbError::Corrupt("remove event without a path"))?;
                Self::apply_remove(tx, seq, *ino, path, false, *mtime_ns)?;
            }
            EventPayload::Rmdir { ino, mtime_ns } => {
                let path = path.ok_or(DbError::Corrupt("remove event without a path"))?;
                Self::apply_remove(tx, seq, *ino, path, true, *mtime_ns)?;
            }
            EventPayload::Link { ino, mtime_ns } => {
                let path = path2
                    .or(path)
                    .ok_or(DbError::Corrupt("link event without a path"))?;
                Self::apply_link(tx, seq, *ino, path, *mtime_ns)?;
            }
            EventPayload::Lock { .. }
            | EventPayload::Unlock { .. }
            | EventPayload::Leave
            | EventPayload::SyncCtrl { .. } => {}
        }
        Ok(())
    }

    /// Concatenate the outbox chunk bytes in chunk order, or `None` when a
    /// chunk is not cached.
    fn outbox_data_in(tx: &WriteTx<'_>, op_id: &[u8; 16]) -> Result<Option<Vec<u8>>, DbError> {
        let mut statement = tx.conn().prepare(
            "SELECT c.data FROM outbox_chunks oc
               LEFT JOIN chunks c ON c.hash = oc.chunk_hash
              WHERE oc.op_id = ?1 ORDER BY oc.chunk_no",
        )?;
        let rows = statement.query_map([op_id.as_slice()], |row| {
            row.get::<_, Option<Vec<u8>>>(0)
        })?;
        let mut data = Vec::new();
        let mut any = false;
        for row in rows {
            let Some(bytes) = row? else {
                return Ok(None);
            };
            data.extend_from_slice(&bytes);
            any = true;
        }
        Ok(if any { Some(data) } else { None })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::client::db::{ClientDb, DbError};
    use crate::client::ops::{AttrChange, CreateAttrs};
    use crate::store::sqlite::{
        ChunkRef, EventPayload, ObjectKind, ROOT_INO, V1_SETATTR_BYTES,
    };
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
    fn replay_applies_version_1_and_version_2_setattrs_in_one_sequence() {
        let (_dir, db) = open();
        let ino = [0x11u8; 16];
        let create = EventPayload::CreateFile {
            ino,
            mode: 0o600,
            uid: 1,
            gid: 2,
            mtime_ns: 1,
            file_root: crate::store::sqlite::file_root(ObjectKind::File, None, &[]),
        };
        db.apply_remote(1, 1, Some([0xc1; 16]), "ok", &create, Some("/a"), None, None)
            .unwrap();
        let (write, _) = write_payload(ino, b"hello");
        db.apply_remote(
            2,
            1,
            Some([0xc2; 16]),
            "ok",
            &write,
            Some("/a"),
            None,
            Some(b"hello"),
        )
        .unwrap();

        // A pre-upgrade row changes attributes only: the size must not move.
        let legacy = EventPayload::decode(EventKind::Setattr, &V1_SETATTR_BYTES).unwrap();
        let outcome = db
            .apply_remote(3, 1, Some([0xc3; 16]), "ok", &legacy, Some("/a"), None, None)
            .unwrap();
        assert_eq!(outcome, super::super::db::ApplyOutcome::Applied);
        let object = db.lookup_by_path("/a").unwrap();
        assert_eq!(object.mode, 0o644);
        assert_eq!(object.size, 5, "a version-1 setattr is attribute-only");
        assert_eq!(db.read_at(ino, 0, 5).unwrap(), b"hello");

        // A current row carries the size and the attributes in one event.
        let current = EventPayload::Setattr {
            ino,
            mode: Some(0o600),
            uid: None,
            gid: None,
            mtime_ns: Some(9),
            size: Some(3),
        };
        db.apply_remote(4, 1, Some([0xc4; 16]), "ok", &current, Some("/a"), None, None)
            .unwrap();
        let object = db.lookup_by_path("/a").unwrap();
        assert_eq!(object.mode, 0o600);
        assert_eq!(object.size, 3);
        assert_eq!(db.read_at(ino, 0, 3).unwrap(), b"hel");
        assert_eq!(db.applied_seq().unwrap(), 4);
    }

    #[test]
    fn a_write_without_its_stream_does_not_advance_applied_seq() {
        let (_dir, db) = open();
        let ino = [0x71; 16];
        let create = EventPayload::CreateFile {
            ino,
            mode: 0o644,
            uid: 1,
            gid: 2,
            mtime_ns: 1,
            file_root: crate::store::sqlite::file_root(ObjectKind::File, None, &[]),
        };
        db.apply_remote(1, 1, Some([0xb1; 16]), "ok", &create, Some("/a"), None, None)
            .unwrap();
        let (write, _) = write_payload(ino, b"hello");

        // The STREAM_DATA fragment was lost: `data` is None and the chunk is
        // not cached locally. The event must not advance the watermark.
        let error = db
            .apply_remote(
                2,
                1,
                Some([0xb2; 16]),
                "ok",
                &write,
                Some("/a"),
                None,
                None,
            )
            .unwrap_err();
        assert!(matches!(error, DbError::MissingChunk(_)));
        assert_eq!(db.applied_seq().unwrap(), 1);

        // A reconnect replays the same sequence with the server's content.
        db.apply_remote(
            2,
            1,
            Some([0xb2; 16]),
            "ok",
            &write,
            Some("/a"),
            None,
            Some(b"hello"),
        )
        .unwrap();
        assert_eq!(db.applied_seq().unwrap(), 2);
        assert_eq!(db.read_at(ino, 0, 5).unwrap(), b"hello");
    }

    #[test]
    fn an_own_rename_echo_replaces_the_local_winner() {
        let (_dir, db) = open();
        let local = db
            .create_file(ROOT_INO, OsStr::new("x"), CreateAttrs::new(0o644, 0, 0))
            .unwrap();
        db.rename(
            ROOT_INO,
            OsStr::new("x"),
            ROOT_INO,
            OsStr::new("y"),
            Default::default(),
        )
        .unwrap();
        let rename_op_id: Vec<u8> = db
            .read()
            .unwrap()
            .conn()
            .query_row(
                "SELECT op_id FROM outbox WHERE kind = 'rename'
                  ORDER BY created_at DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let rename_op_id: [u8; 16] = rename_op_id.try_into().unwrap();

        // The server resolves /x to another client's inode and renames that.
        let other = [0xbb; 16];
        let create_other = EventPayload::CreateFile {
            ino: other,
            mode: 0o644,
            uid: 1,
            gid: 2,
            mtime_ns: 1,
            file_root: crate::store::sqlite::file_root(ObjectKind::File, None, &[]),
        };
        db.apply_remote(
            1,
            1,
            Some([0xc1; 16]),
            "ok",
            &create_other,
            Some("/z"),
            None,
            None,
        )
        .unwrap();
        db.apply_remote(
            2,
            1,
            Some(rename_op_id),
            "ok",
            &EventPayload::Rename {
                ino: other,
                mtime_ns: Some(2),
            },
            Some("/x"),
            Some("/y"),
            None,
        )
        .unwrap();

        assert_eq!(db.lookup_by_path("/y").unwrap().ino, other);
        assert_eq!(db.lookup_by_path("/z").unwrap().ino, other);
        assert!(db.lookup_by_path("/x").is_err());
        // The optimistic local winner lost its only name.
        assert!(db.getattr(local.ino).is_err());
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
    fn fast_forward_keeps_the_replica_and_moves_the_watermark() {
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
        db.create_file(ino, OsStr::new("local"), CreateAttrs::new(0o644, 0, 0))
            .unwrap();
        let pending = db.outbox_count(super::super::db::OutboxState::Pending).unwrap();

        db.fast_forward(2, 9).unwrap();

        assert_eq!(db.epoch().unwrap(), 2);
        assert_eq!(db.applied_seq().unwrap(), 9);
        assert!(db.lookup_by_path("/d").is_ok());
        assert!(db.lookup_by_path("/d/local").is_ok());
        assert!(db.has_content().unwrap());
        // Local intent survives; it is not part of the adopted watermark.
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
        let source_root = source.getattr(ROOT_INO).unwrap();
        let target_root = target.getattr(ROOT_INO).unwrap();
        assert_eq!(target_root.mode, source_root.mode);
        assert_eq!(target_root.uid, source_root.uid);
        assert_eq!(target_root.gid, source_root.gid);
        assert_eq!(target_root.mtime_ns, source_root.mtime_ns);
        let source_dir = source.lookup_by_path("/d").unwrap();
        let target_dir = target.lookup_by_path("/d").unwrap();
        assert_eq!(target_dir.mtime_ns, source_dir.mtime_ns);
        assert!(target.check_replica().unwrap().is_empty());
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
            &EventPayload::Rename {
                ino: file_ino,
                mtime_ns: Some(3),
            },
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
            &EventPayload::Unlink {
                ino: file_ino,
                mtime_ns: Some(4),
            },
            Some("/d/g"),
            None,
            None,
        )
        .unwrap();
        assert!(db.lookup_by_path("/d/g").is_err());
        assert!(db.getattr(file_ino).is_err());
        assert!(matches!(db.lookup_by_path("/d/g"), Err(DbError::Errno(Errno::ENOENT))));
    }

    fn dir_payload(ino: Ino) -> EventPayload {
        EventPayload::CreateDir {
            ino,
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime_ns: 1,
            file_root: crate::store::sqlite::file_root(ObjectKind::Dir, None, &[]),
        }
    }

    fn file_payload(ino: Ino) -> EventPayload {
        EventPayload::CreateFile {
            ino,
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime_ns: 1,
            file_root: crate::store::sqlite::file_root(ObjectKind::File, None, &[]),
        }
    }

    fn replay(
        db: &ClientDb,
        seq: i64,
        payload: &EventPayload,
        path: &str,
        path2: Option<&str>,
        data: Option<&[u8]>,
    ) {
        let outcome = db
            .apply_remote(
                seq,
                1,
                Some([seq as u8; 16]),
                "ok",
                payload,
                Some(path),
                path2,
                data,
            )
            .unwrap();
        assert_eq!(outcome, super::super::db::ApplyOutcome::Applied);
    }

    #[test]
    fn replay_skips_events_the_client_already_deleted() {
        let (_dir, db) = open();
        let dir_ino = [5u8; 16];
        let file_ino = [6u8; 16];
        let (write, _) = write_payload(file_ino, b"hello");

        replay(&db, 1, &dir_payload(dir_ino), "/d", None, None);
        replay(&db, 2, &file_payload(file_ino), "/d/f", None, None);
        replay(&db, 3, &write, "/d/f", None, Some(b"hello"));

        // The client's own unlink and rmdir land before the server's stream
        // reaches the matching events.
        db.unlink(dir_ino, OsStr::new("f")).unwrap();
        db.rmdir(ROOT_INO, OsStr::new("d")).unwrap();
        assert!(db.lookup_by_path("/d").is_err());

        // The server's stream still carries the write, a rename, the child
        // unlink and the directory rmdir. All four must pass without Fatal.
        replay(&db, 4, &write, "/d/f", None, Some(b"hello"));
        replay(
            &db,
            5,
            &EventPayload::Rename {
                ino: file_ino,
                mtime_ns: Some(5),
            },
            "/d/f",
            Some("/d/g"),
            None,
        );
        replay(
            &db,
            6,
            &EventPayload::Unlink {
                ino: file_ino,
                mtime_ns: Some(6),
            },
            "/d/g",
            None,
            None,
        );
        replay(
            &db,
            7,
            &EventPayload::Rmdir {
                ino: dir_ino,
                mtime_ns: Some(7),
            },
            "/d",
            None,
            None,
        );

        assert_eq!(db.applied_seq().unwrap(), 7);
        assert!(matches!(db.lookup_by_path("/d"), Err(DbError::Errno(Errno::ENOENT))));
        assert!(matches!(db.lookup_by_path("/d/f"), Err(DbError::Errno(Errno::ENOENT))));
        assert!(matches!(db.lookup_by_path("/d/g"), Err(DbError::Errno(Errno::ENOENT))));
        assert!(db.getattr(file_ino).is_err());
        // The write, the rename and the unlink diverged; the rmdir's name was
        // already gone (the ordinary echo path).
        assert_eq!(db.replay_skipped().unwrap(), 3);
    }

    #[test]
    fn replay_skips_missing_parents_and_objects() {
        let (_dir, db) = open();
        let dir_ino = [7u8; 16];
        let file_ino = [8u8; 16];
        replay(&db, 1, &dir_payload(dir_ino), "/d", None, None);
        replay(&db, 2, &file_payload(file_ino), "/d/f", None, None);
        db.unlink(dir_ino, OsStr::new("f")).unwrap();
        db.rmdir(ROOT_INO, OsStr::new("d")).unwrap();

        replay(&db, 3, &file_payload([9u8; 16]), "/d/g", None, None);
        replay(
            &db,
            4,
            &EventPayload::Link {
                ino: file_ino,
                mtime_ns: Some(4),
            },
            "/e",
            None,
            None,
        );
        replay(
            &db,
            5,
            &EventPayload::Rename {
                ino: file_ino,
                mtime_ns: Some(5),
            },
            "/d/f",
            Some("/x/f"),
            None,
        );
        replay(
            &db,
            6,
            &EventPayload::Link {
                ino: [9u8; 16],
                mtime_ns: Some(6),
            },
            "/d/g",
            None,
            None,
        );

        assert_eq!(db.applied_seq().unwrap(), 6);
        assert!(db.lookup_by_path("/d").is_err());
        assert!(db.lookup_by_path("/e").is_err());
        assert!(db.lookup_by_path("/x/f").is_err());
        assert_eq!(db.replay_skipped().unwrap(), 4);
    }

    fn event(
        seq: i64,
        payload: &EventPayload,
        path: Option<&str>,
        path2: Option<&str>,
        data: Option<&[u8]>,
    ) -> RemoteEvent {
        RemoteEvent {
            seq,
            epoch: 1,
            op_id: Some([seq as u8; 16]),
            result: "ok".to_owned(),
            payload: payload.clone(),
            path: path.map(str::to_owned),
            path2: path2.map(str::to_owned),
            data: data.map(<[u8]>::to_vec),
        }
    }

    #[test]
    fn a_batch_commits_many_events_in_one_transaction() {
        let (_dir, db) = open();
        let ino = [0x31u8; 16];
        let create = file_payload(ino);
        let (write, _) = write_payload(ino, b"batched");
        let events = [
            event(1, &create, Some("/a"), None, None),
            event(2, &write, Some("/a"), None, Some(b"batched")),
            event(
                3,
                &EventPayload::Setattr {
                    ino,
                    mode: Some(0o600),
                    uid: None,
                    gid: None,
                    mtime_ns: None,
                    size: None,
                },
                Some("/a"),
                None,
                None,
            ),
        ];
        let report = db.apply_remote_batch(&events).unwrap();
        assert_eq!(
            report.outcomes,
            vec![
                ApplyOutcome::Applied,
                ApplyOutcome::Applied,
                ApplyOutcome::Applied
            ]
        );
        assert_eq!(report.applied_seq, 3);
        assert!(!report.rejected);
        assert_eq!(db.applied_seq().unwrap(), 3);
        assert_eq!(db.read_at(ino, 0, 7).unwrap(), b"batched");
        assert_eq!(db.lookup_by_path("/a").unwrap().mode, 0o600);
    }

    #[test]
    fn a_gap_rolls_the_whole_batch_back() {
        let (_dir, db) = open();
        let first = file_payload([0x32u8; 16]);
        let second = file_payload([0x33u8; 16]);
        let events = [
            event(1, &first, Some("/a"), None, None),
            event(3, &second, Some("/b"), None, None),
        ];
        let error = db.apply_remote_batch(&events).unwrap_err();
        assert!(matches!(error, DbError::Corrupt("event sequence gap")));
        assert_eq!(db.applied_seq().unwrap(), 0);
        assert!(db.lookup_by_path("/a").is_err());
        assert!(db.lookup_by_path("/b").is_err());
    }

    #[test]
    fn a_duplicate_inside_a_batch_is_skipped() {
        let (_dir, db) = open();
        let first = file_payload([0x34u8; 16]);
        let second = file_payload([0x35u8; 16]);
        let events = [
            event(1, &first, Some("/a"), None, None),
            event(2, &second, Some("/b"), None, None),
        ];
        db.apply_remote_batch(&events[..1]).unwrap();
        let report = db.apply_remote_batch(&events).unwrap();
        assert_eq!(
            report.outcomes,
            vec![ApplyOutcome::Duplicate, ApplyOutcome::Applied]
        );
        assert_eq!(report.applied_seq, 2);
        assert!(db.lookup_by_path("/a").is_ok());
        assert!(db.lookup_by_path("/b").is_ok());
    }

    #[test]
    fn a_rejection_stops_the_batch_and_keeps_the_prefix() {
        let (_dir, db) = open();
        let first = file_payload([0x36u8; 16]);
        let second = file_payload([0x37u8; 16]);
        let mut rejected = event(2, &second, Some("/b"), None, None);
        rejected.result = "rejected".to_owned();
        let events = [
            event(1, &first, Some("/a"), None, None),
            rejected,
            event(3, &second, Some("/c"), None, None),
        ];
        let report = db.apply_remote_batch(&events).unwrap();
        assert!(report.rejected);
        assert_eq!(
            report.outcomes,
            vec![ApplyOutcome::Applied, ApplyOutcome::Rejected]
        );
        assert_eq!(db.applied_seq().unwrap(), 2);
        assert!(db.lookup_by_path("/a").is_ok());
        assert!(db.lookup_by_path("/c").is_err());
        assert!(db.needs_resync().unwrap());
    }

    #[test]
    fn a_committed_batch_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.db");
        let ino = [0x38u8; 16];
        {
            let db = ClientDb::open(&path, [9u8; 16]).unwrap();
            let (write, _) = write_payload(ino, b"durable batch");
            let events = [
                event(1, &file_payload(ino), Some("/a"), None, None),
                event(2, &write, Some("/a"), None, Some(b"durable batch")),
            ];
            let report = db.apply_remote_batch(&events).unwrap();
            assert_eq!(report.applied_seq, 2);
        }
        let again = ClientDb::open(&path, [9u8; 16]).unwrap();
        assert_eq!(again.applied_seq().unwrap(), 2);
        assert_eq!(again.read_at(ino, 0, 13).unwrap(), b"durable batch");
    }

    fn dir_payload_mtime(ino: Ino, mtime_ns: i64) -> EventPayload {
        EventPayload::CreateDir {
            ino,
            mode: 0o755,
            uid: 1,
            gid: 2,
            mtime_ns,
            file_root: crate::store::sqlite::file_root(ObjectKind::Dir, None, &[]),
        }
    }

    fn file_payload_mtime(ino: Ino, mtime_ns: i64) -> EventPayload {
        EventPayload::CreateFile {
            ino,
            mode: 0o644,
            uid: 3,
            gid: 4,
            mtime_ns,
            file_root: crate::store::sqlite::file_root(ObjectKind::File, None, &[]),
        }
    }

    fn object_state(db: &ClientDb, ino: Ino) -> (i64, i64, i64) {
        let tx = db.read().unwrap();
        let row = tx
            .conn()
            .query_row(
                "SELECT deleted, nlink,
                        (SELECT COUNT(*) FROM names WHERE names.ino = objects.ino)
                   FROM objects WHERE ino = ?1",
                [ino.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        row
    }

    #[test]
    fn create_remove_rename_and_link_events_stamp_directories() {
        let (_dir, db) = open();
        let a = [0x41u8; 16];
        let f = [0x42u8; 16];
        let b = [0x43u8; 16];

        replay(&db, 1, &dir_payload_mtime(a, 100), "/a", None, None);
        assert_eq!(db.getattr(ROOT_INO).unwrap().mtime_ns, 100);
        replay(&db, 2, &file_payload_mtime(f, 200), "/a/f", None, None);
        assert_eq!(db.getattr(a).unwrap().mtime_ns, 200);
        assert_eq!(db.getattr(ROOT_INO).unwrap().mtime_ns, 100);

        replay(
            &db,
            3,
            &EventPayload::Rename {
                ino: f,
                mtime_ns: Some(300),
            },
            "/a/f",
            Some("/a/g"),
            None,
        );
        assert_eq!(db.getattr(f).unwrap().mtime_ns, 300);
        assert_eq!(db.getattr(a).unwrap().mtime_ns, 300);

        replay(&db, 4, &dir_payload_mtime(b, 400), "/b", None, None);
        replay(
            &db,
            5,
            &EventPayload::Link {
                ino: f,
                mtime_ns: Some(500),
            },
            "/b/h",
            None,
            None,
        );
        assert_eq!(db.getattr(b).unwrap().mtime_ns, 500);
        assert_eq!(db.getattr(a).unwrap().mtime_ns, 300);
        assert_eq!(db.getattr(f).unwrap().nlink, 2);

        replay(
            &db,
            6,
            &EventPayload::Unlink {
                ino: f,
                mtime_ns: Some(600),
            },
            "/a/g",
            None,
            None,
        );
        assert_eq!(db.getattr(a).unwrap().mtime_ns, 600);
        assert_eq!(db.getattr(f).unwrap().nlink, 1);

        replay(
            &db,
            7,
            &EventPayload::Rmdir {
                ino: a,
                mtime_ns: Some(700),
            },
            "/a",
            None,
            None,
        );
        assert_eq!(db.getattr(ROOT_INO).unwrap().mtime_ns, 700);
        assert!(db.check_replica().unwrap().is_empty());
    }

    #[test]
    fn rmdir_tombstones_the_directory_instead_of_leaving_a_nameless_row() {
        let (_dir, db) = open();
        let d = [0x51u8; 16];
        replay(&db, 1, &dir_payload_mtime(d, 10), "/d", None, None);
        assert_eq!(db.getattr(ROOT_INO).unwrap().nlink, 3);

        replay(
            &db,
            2,
            &EventPayload::Rmdir {
                ino: d,
                mtime_ns: Some(20),
            },
            "/d",
            None,
            None,
        );

        assert_eq!(db.getattr(ROOT_INO).unwrap().nlink, 2);
        assert_eq!(object_state(&db, d), (1, 0, 0));
        assert!(db.check_replica().unwrap().is_empty());
    }

    #[test]
    fn repair_tombstones_nameless_live_rows_and_fixes_links() {
        let (_dir, db) = open();
        let d = [0x61u8; 16];
        replay(&db, 1, &dir_payload_mtime(d, 10), "/d", None, None);

        // Reproduce the old rmdir bug: the name is gone but the object stays
        // live with a decremented link count.
        db.write(|tx| {
            tx.delete_name(ROOT_INO, "d")?;
            let mut object = ClientDb::object_in(tx, d)?.unwrap();
            object.nlink = 1;
            tx.put_object(&object)?;
            Ok(())
        })
        .unwrap();

        let issues = db.check_replica().unwrap();
        assert!(issues.iter().any(|issue| matches!(
            issue,
            ReplicaIssue::LiveObjectWithoutName { ino } if *ino == d
        )));

        let report = db.repair_replica_metadata().unwrap();
        assert_eq!(report.tombstones, 1);
        assert!(report.changed());
        assert_eq!(object_state(&db, d), (1, 0, 0));
        assert!(db.check_replica().unwrap().is_empty());
    }

    #[test]
    fn remove_events_leave_tombstones_for_objects_the_replica_never_held() {
        let (_dir, db) = open();
        let dir = [0xa1u8; 16];
        let file = [0xa2u8; 16];
        replay(
            &db,
            1,
            &EventPayload::Rmdir {
                ino: dir,
                mtime_ns: Some(10),
            },
            "/gone",
            None,
            None,
        );
        replay(
            &db,
            2,
            &EventPayload::Unlink {
                ino: file,
                mtime_ns: Some(20),
            },
            "/missing",
            None,
            None,
        );
        assert_eq!(object_state(&db, dir), (1, 0, 0));
        assert_eq!(object_state(&db, file), (1, 0, 0));
        assert!(db.check_replica().unwrap().is_empty());
    }

    #[test]
    fn repair_removes_dangling_names_and_rebuilds_paths() {
        let (_dir, db) = open();
        let f = [0x71u8; 16];
        let ghost = [0x72u8; 16];
        replay(&db, 1, &file_payload_mtime(f, 10), "/f", None, None);
        replay(
            &db,
            2,
            &file_payload_mtime(ghost, 10),
            "/ghost",
            None,
            None,
        );
        db.write(|tx| {
            // A tombstone that still carries a name: the name is invisible
            // through the mount but breaks the object/name invariant.
            let mut object = ClientDb::object_in(tx, ghost)?.unwrap();
            object.deleted = true;
            object.nlink = 0;
            tx.put_object(&object)?;
            tx.conn().execute(
                "UPDATE names SET path = '/wrong' WHERE parent = ?1 AND name = 'f'",
                [ROOT_INO.as_slice()],
            )?;
            Ok(())
        })
        .unwrap();

        let issues = db.check_replica().unwrap();
        assert!(issues
            .iter()
            .any(|issue| matches!(issue, ReplicaIssue::NameToDeletedObject { .. })));
        assert!(issues
            .iter()
            .any(|issue| matches!(issue, ReplicaIssue::PathMismatch { .. })));

        let report = db.repair_replica_metadata().unwrap();
        assert_eq!(report.names_removed, 1);
        assert_eq!(report.paths, 1);
        assert!(db.check_replica().unwrap().is_empty());
        assert_eq!(db.lookup_by_path("/f").unwrap().ino, f);
    }

    #[test]
    fn repair_tombstones_the_children_of_a_nameless_directory() {
        let (_dir, db) = open();
        let d = [0x91u8; 16];
        let e = [0x92u8; 16];
        let f = [0x93u8; 16];
        replay(&db, 1, &dir_payload_mtime(d, 10), "/d", None, None);
        replay(&db, 2, &dir_payload_mtime(e, 20), "/d/e", None, None);
        replay(&db, 3, &file_payload_mtime(f, 30), "/d/e/f", None, None);

        db.write(|tx| {
            tx.delete_name(ROOT_INO, "d")?;
            let mut object = ClientDb::object_in(tx, d)?.unwrap();
            object.nlink = 1;
            tx.put_object(&object)?;
            Ok(())
        })
        .unwrap();

        let report = db.repair_replica_metadata().unwrap();
        assert_eq!(report.tombstones, 3);
        assert_eq!(object_state(&db, d), (1, 0, 0));
        assert_eq!(object_state(&db, e), (1, 0, 0));
        assert_eq!(object_state(&db, f), (1, 0, 0));
        assert!(db.check_replica().unwrap().is_empty());
    }

    #[test]
    fn setattr_without_a_size_still_applies_its_mtime() {
        let (_dir, db) = open();
        let f = [0x81u8; 16];
        replay(&db, 1, &file_payload_mtime(f, 10), "/f", None, None);
        replay(
            &db,
            2,
            &EventPayload::Setattr {
                ino: f,
                mode: None,
                uid: None,
                gid: None,
                mtime_ns: Some(99),
                size: None,
            },
            "/f",
            None,
            None,
        );
        assert_eq!(db.getattr(f).unwrap().mtime_ns, 99);
    }

    #[test]
    fn a_local_mtime_only_setattr_keeps_its_timestamp_in_the_outbox() {
        let (_dir, db) = open();
        let file = db
            .create_file(ROOT_INO, OsStr::new("f"), CreateAttrs::new(0o644, 1, 2))
            .unwrap();
        let changed = db
            .setattr(
                file.ino,
                AttrChange {
                    mtime_ns: Some(123),
                    ..AttrChange::default()
                },
            )
            .unwrap();
        assert_eq!(changed.mtime_ns, 123);
        let rows = db.outbox_page(10).unwrap();
        match &rows.last().unwrap().decoded {
            EventPayload::Setattr {
                ino,
                mtime_ns,
                size,
                ..
            } => {
                assert_eq!(*ino, file.ino);
                assert_eq!(*mtime_ns, Some(123));
                assert_eq!(*size, None);
            }
            other => panic!("expected a setattr row, got {other:?}"),
        }
    }
}
