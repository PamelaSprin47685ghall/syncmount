//! Signatures, upload begin/commit/abort and batch status.
//!
//! A commit is reconstructed into the spool first. Only after every file has
//! matched its manifest `size`, `content_hash` and `file_root` does one
//! `BEGIN IMMEDIATE` transaction replace the directory's direct entries. Any
//! failure rolls the whole transaction back.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::mmap::base;
use crate::mmap::db::{MmDb, MmTx, ReadTx, WriteTx};
use crate::mmap::proto::{
    Aborted, BatchState, BatchStateMessage, BlockSignature as WireBlockSignature, ErrorCode,
    FileSignature, Instruction as CommitStep, InstructionReader, SignatureRequest, SignatureState,
    Signatures, UploadAbort, UploadBegin, UploadCommit, UploadMode, UploadPlan, UploadResult,
};
use crate::mmap::rsync::{MAX_BLOCKS, block_count_for, block_size_for, strong128};
use crate::mmap::types::{
    BatchId, BatchRecord, DirAttrs, DirRecord, DirSeq, EntryKind, EntryOp, FileRecord, Hash, Ino,
    LockId, LockRecord, ManifestEntry, MmBase, MmSeq, Phase, UploadRecord, UploadState,
    VersionRecord,
};
use crate::mmap::{Manifest, now_ms};
use crate::store::sqlite::ChunkRef;

use super::checkout::read_range;
use super::http::{self, Response};
use super::lock::check_lock;
use super::manifest::{assign_entries, plan, validate_entries, wire_manifest_hash};
use super::spool::{BeginRecord, Spool};
use super::{
    COMMIT_LOCK_EXTENSION_MS, Fault, RENEW_PROGRESS_BYTES, ServerState, SessionInfo, child_path,
    path_is_within,
};

impl ServerState {
    /// `SIGNATURES_REQ`: per-file block signatures over the locked base.
    pub fn signatures(
        &self,
        request: SignatureRequest,
        session: SessionInfo,
    ) -> Result<Response, Fault> {
        self.check_wire_namespace(&request.namespace)?;
        let tx = self.read()?;
        let Some(dir) = tx.dir_by_path(&request.dir_path)? else {
            return Err(Fault::detail(ErrorCode::DirNotFound, "directory not found"));
        };
        if request.dir_ino != dir.ino {
            return Err(Fault::detail(
                ErrorCode::DirNotFound,
                "directory inode changed",
            ));
        }
        let lock_id = LockId::from_bytes(request.lock_id);
        let batch_id = BatchId::from_bytes(request.batch_id);
        check_lock(&tx, lock_id, session, &request.dir_path)?;
        let Some(upload) = tx.upload(batch_id)? else {
            return Err(Fault::detail(ErrorCode::BatchNotFound, "batch not found"));
        };
        if upload.lock_id != lock_id {
            return Err(Fault::lock_lost("batch belongs to another lock"));
        }
        if upload.state == UploadState::Aborted {
            return Err(Fault::detail(ErrorCode::BatchAborted, "batch is aborted"));
        }
        if request.epoch != upload.base_epoch
            || request.base_seq != upload.base_seq.get()
            || request.dir_version != upload.dir_version
            || tx.epoch()? != request.epoch
            || dir.base.dir_version != request.dir_version
        {
            return Err(Fault::base_changed(&dir, tx.mm_seq()?, request.base_seq));
        }

        let mut files = Vec::with_capacity(request.files.len());
        for file in &request.files {
            let current = tx.file_by_name(dir.ino, &file.name)?;
            let current = current.filter(|record| record.kind == EntryKind::File);
            if let Some(record) = current {
                if record.file_root == file.local_file_root && record.size == file.size {
                    files.push(FileSignature {
                        name: file.name.clone(),
                        ino: record.ino,
                        size: record.size,
                        file_root: record.file_root,
                        state: SignatureState::Unchanged,
                        block_size: block_size_for(record.size),
                        block_count: 0,
                        blocks: Vec::new(),
                    });
                    continue;
                }
                let block_size = block_size_for(record.size);
                let block_count = block_count_for(record.size, block_size);
                if block_count > MAX_BLOCKS {
                    files.push(full_signature(file, &record, block_size));
                    continue;
                }
                let mut blocks = Vec::with_capacity(usize::try_from(block_count).unwrap_or(0));
                for index in 0..block_count {
                    let index = u32::try_from(index).map_err(|_| {
                        Fault::detail(ErrorCode::Internal, "block index does not fit u32")
                    })?;
                    let bytes = read_block(&tx, &record, index, block_size)?;
                    blocks.push(WireBlockSignature {
                        weak: crate::mmap::rsync::weak(&bytes),
                        strong: strong128(&bytes),
                        block_len: u32::try_from(bytes.len()).map_err(|_| {
                            Fault::detail(ErrorCode::Internal, "block length does not fit u32")
                        })?,
                    });
                }
                files.push(FileSignature {
                    name: file.name.clone(),
                    ino: record.ino,
                    size: record.size,
                    file_root: record.file_root,
                    state: SignatureState::Delta,
                    block_size,
                    block_count: u32::try_from(block_count).map_err(|_| {
                        Fault::detail(ErrorCode::Internal, "block count does not fit u32")
                    })?,
                    blocks,
                });
            } else {
                let ino = tx
                    .file_by_name(dir.ino, &file.name)?
                    .map(|record| record.ino)
                    .or(file.ino)
                    .unwrap_or([0u8; 16]);
                files.push(FileSignature {
                    name: file.name.clone(),
                    ino,
                    size: file.size,
                    file_root: file.local_file_root,
                    state: SignatureState::Full,
                    block_size: block_size_for(file.size),
                    block_count: 0,
                    blocks: Vec::new(),
                });
            }
        }
        let message = Signatures {
            epoch: request.epoch,
            base_seq: request.base_seq,
            dir_version: request.dir_version,
            files,
        };
        http::message_response(&message)
    }

    /// `UPLOAD_BEGIN`.
    pub async fn upload_begin(
        &self,
        request: UploadBegin,
        session: SessionInfo,
    ) -> Result<Response, Fault> {
        self.check_wire_namespace(&request.namespace)?;
        if request.client_id != session.client_id {
            return Err(Fault::detail(
                ErrorCode::AuthFailed,
                "upload client id differs from the session",
            ));
        }
        let batch_id = BatchId::from_bytes(request.batch_id);
        let lock_id = LockId::from_bytes(request.lock_id);
        let mut db = self.writer().lock().await;
        let tx = db.write()?;
        let Some(dir) = tx.dir_by_path(&request.dir_path)? else {
            return Err(Fault::detail(ErrorCode::DirNotFound, "directory not found"));
        };
        if request.dir_ino != dir.ino {
            return Err(Fault::detail(
                ErrorCode::DirNotFound,
                "directory inode changed",
            ));
        }
        let lock = check_lock(&tx, lock_id, session, &request.dir_path)?;
        if let Some(batch) = tx.batch(batch_id)? {
            if batch.manifest_hash == request.manifest_hash {
                return Err(Fault::detail(
                    ErrorCode::BatchCommitted,
                    "batch is already committed",
                ));
            }
            return Err(Fault::detail(
                ErrorCode::BatchConflict,
                "batch id was used for a different manifest",
            ));
        }
        if request.epoch != dir.base.epoch
            || request.base_seq != dir.base.dir_seq.get()
            || request.dir_version != dir.base.dir_version
            || request.epoch != tx.epoch()?
        {
            return Err(Fault::base_changed(&dir, tx.mm_seq()?, request.base_seq));
        }
        let computed = wire_manifest_hash(&request.entries)?;
        if computed != request.manifest_hash {
            return Err(Fault::detail(
                ErrorCode::ManifestInvalid,
                "manifest_hash does not match the entries",
            ));
        }
        let current = tx.files(dir.ino)?;
        let locks = unexpired_locks(&tx)?;
        validate_entries(&current, &request.entries, &locks, &request.dir_path)?;
        let mut total_bytes = 0u64;
        for entry in &request.entries {
            if entry.kind == crate::mmap::proto::EntryKind::File
                && entry.op == crate::mmap::proto::EntryOp::Put
            {
                total_bytes = total_bytes.saturating_add(entry.size);
            }
        }
        if total_bytes > self.config().limits.max_batch_bytes {
            return Err(Fault::detail(
                ErrorCode::TooLarge,
                "batch content exceeds the size limit",
            ));
        }
        check_provided_inos(&tx, &request.entries, &current)?;
        let assigned = assign_entries(&request.entries, &current)?;
        let base_entries = tx.base_manifest(dir.ino)?;
        let items = plan(&base_entries, &assigned, request.mode)?;
        let attrs = typed_attrs(&request.dir_attrs)?;
        let record = BeginRecord {
            entries: assigned,
            dir_attrs: attrs,
            mode: request.mode.as_u32() as u8,
        };

        if let Some(existing) = tx.upload(batch_id)? {
            if existing.state == UploadState::Aborted {
                return Err(Fault::detail(ErrorCode::BatchAborted, "batch is aborted"));
            }
            if existing.manifest_hash != request.manifest_hash {
                return Err(Fault::detail(
                    ErrorCode::BatchConflict,
                    "batch id carries a different manifest",
                ));
            }
            if existing.lock_id != lock_id {
                return Err(Fault::lock_lost("batch belongs to another lock"));
            }
            let expires = u64::try_from(lock.expires_at_ms).unwrap_or(u64::MAX);
            tx.commit()?;
            drop(db);
            return http::message_response(&UploadPlan {
                batch_id: request.batch_id,
                epoch: request.epoch,
                base_seq: request.base_seq,
                dir_version: request.dir_version,
                plan: items,
                lock_expires_at_ms: expires,
                limits: self.config().limits,
            });
        }

        if let Some(other) = lock.batch_id {
            if other != batch_id {
                if let Some(upload) = tx.upload(other)? {
                    if upload.state != UploadState::Aborted && upload.state != UploadState::Verified
                    {
                        return Err(Fault::detail(
                            ErrorCode::BatchConflict,
                            "the lock already owns an open batch",
                        ));
                    }
                }
            }
        }

        let spool_path = self.spool().batch_dir(batch_id);
        self.spool().create_batch(batch_id)?;
        if let Err(error) = self.spool().write_begin(batch_id, &record) {
            self.spool().remove_batch(batch_id);
            return Err(error);
        }
        let now = now_ms();
        let upload = UploadRecord {
            batch_id,
            lock_id,
            dir_path: dir.path.clone(),
            dir_ino: dir.ino,
            base_epoch: dir.base.epoch,
            base_seq: dir.base.dir_seq,
            dir_version: dir.base.dir_version,
            manifest_hash: request.manifest_hash,
            state: UploadState::Open,
            spool_path: spool_path.to_string_lossy().into_owned(),
            bytes_received: 0,
            created_at_ms: now,
            updated_at_ms: now,
            expires_at_ms: lock.expires_at_ms,
        };
        tx.put_upload(&upload)?;
        tx.put_lock(&LockRecord {
            batch_id: Some(batch_id),
            ..lock.clone()
        })?;
        tx.commit()?;
        drop(db);
        http::message_response(&UploadPlan {
            batch_id: request.batch_id,
            epoch: request.epoch,
            base_seq: request.base_seq,
            dir_version: request.dir_version,
            plan: items,
            lock_expires_at_ms: u64::try_from(lock.expires_at_ms).unwrap_or(u64::MAX),
            limits: self.config().limits,
        })
    }

    /// `UPLOAD_COMMIT`.
    pub async fn upload_commit(
        &self,
        request: UploadCommit,
        session: SessionInfo,
        payload: Option<&Path>,
    ) -> Result<Response, Fault> {
        self.check_wire_namespace(&request.namespace)?;
        let batch_id = BatchId::from_bytes(request.batch_id);
        let lock_id = LockId::from_bytes(request.lock_id);

        let upload = {
            let tx = self.read()?;
            if let Some(batch) = tx.batch(batch_id)? {
                if batch.manifest_hash != request.manifest_hash {
                    return Err(Fault::detail(
                        ErrorCode::BatchConflict,
                        "batch id carries a different manifest",
                    ));
                }
                return http::message_response(&batch_result(&batch));
            }
            let Some(upload) = tx.upload(batch_id)? else {
                return Err(Fault::detail(ErrorCode::BatchNotFound, "batch not found"));
            };
            if upload.state == UploadState::Aborted {
                return Err(Fault::detail(ErrorCode::BatchAborted, "batch is aborted"));
            }
            if upload.manifest_hash != request.manifest_hash {
                return Err(Fault::detail(
                    ErrorCode::BatchConflict,
                    "manifest_hash differs from begin",
                ));
            }
            if upload.lock_id != lock_id {
                return Err(Fault::lock_lost("batch belongs to another lock"));
            }
            check_lock(&tx, lock_id, session, &upload.dir_path)?;
            let Some(dir) = tx.dir_by_path(&upload.dir_path)? else {
                return Err(Fault::detail(ErrorCode::DirNotFound, "directory not found"));
            };
            if request.epoch != upload.base_epoch
                || request.base_seq != upload.base_seq.get()
                || request.dir_version != upload.dir_version
                || tx.epoch()? != request.epoch
                || dir.base.dir_version != upload.dir_version
                || dir.base.dir_seq != upload.base_seq
            {
                return Err(Fault::base_changed(&dir, tx.mm_seq()?, request.base_seq));
            }
            upload
        };

        let begin = self.spool().read_begin(batch_id)?;
        let Some(payload_path) = payload else {
            return Err(Fault::instruction("commit carries no instruction stream"));
        };
        let payload_path = payload_path.to_path_buf();

        // Extend the lease before a reconstruction that may take minutes.
        {
            let mut db = self.writer().lock().await;
            let tx = db.write()?;
            let Some(lock) = tx.lock(lock_id)? else {
                return Err(Fault::lock_lost("lock disappeared"));
            };
            if lock.owner_client != session.client_id {
                return Err(Fault::lock_lost("lock belongs to another client"));
            }
            if lock.expires_at_ms < now_ms() {
                return Err(Fault::lock_expired(&lock));
            }
            let expires = now_ms()
                .saturating_add(i64::try_from(COMMIT_LOCK_EXTENSION_MS).unwrap_or(i64::MAX));
            tx.renew_lock(lock_id, expires, upload.bytes_received)?;
            tx.update_upload_progress(batch_id, upload.bytes_received, expires)?;
            tx.commit()?;
        }

        let read_tx = self.read()?;
        let spool = self.spool().clone();
        let entries = begin.entries.clone();
        let mode = begin.mode()?;
        let dir_ino = upload.dir_ino;
        let db_path = self.config().db_path.clone();
        let namespace = self.config().namespace.clone();
        let reconstructed = tokio::task::spawn_blocking(move || {
            reconstruct(
                read_tx,
                &spool,
                batch_id,
                dir_ino,
                &entries,
                mode,
                &payload_path,
                db_path,
                namespace,
                lock_id,
            )
        })
        .await
        .map_err(|error| Fault::detail(ErrorCode::Internal, format!("rebuild task: {error}")))??;

        let attrs = begin.dir_attrs;
        let mut db = self.writer().lock().await;
        let result = apply_commit(
            &mut db,
            &request,
            batch_id,
            lock_id,
            session,
            &begin.entries,
            &attrs,
            &reconstructed,
        )?;
        drop(db);
        self.spool().remove_batch(batch_id);
        http::message_response(&result)
    }

    /// `UPLOAD_ABORT`.
    pub async fn upload_abort(
        &self,
        request: UploadAbort,
        session: SessionInfo,
    ) -> Result<Response, Fault> {
        let batch_id = BatchId::from_bytes(request.batch_id);
        let lock_id = LockId::from_bytes(request.lock_id);
        let mut db = self.writer().lock().await;
        let tx = db.write()?;
        if tx.batch(batch_id)?.is_some() {
            return Err(Fault::detail(
                ErrorCode::BatchCommitted,
                "batch is already committed",
            ));
        }
        let Some(upload) = tx.upload(batch_id)? else {
            return Err(Fault::detail(ErrorCode::BatchNotFound, "batch not found"));
        };
        if upload.lock_id != lock_id {
            return Err(Fault::lock_lost("batch belongs to another lock"));
        }
        if upload.state == UploadState::Aborted {
            tx.commit()?;
            drop(db);
            self.spool().remove_batch(batch_id);
            return Ok(http::empty_response(204));
        }
        if let Some(lock) = tx.lock(lock_id)? {
            if lock.owner_client != session.client_id {
                return Err(Fault::lock_lost("lock belongs to another client"));
            }
            tx.delete_lock(lock_id)?;
        }
        tx.set_upload_state(batch_id, UploadState::Aborted)?;
        tx.commit()?;
        drop(db);
        self.spool().remove_batch(batch_id);
        http::message_response(&Aborted {
            batch_id: request.batch_id,
            reason: None,
        })
    }

    /// `GET batch/{id}`.
    pub fn batch_status(&self, batch_id: [u8; 16]) -> Result<Response, Fault> {
        let batch_id = BatchId::from_bytes(batch_id);
        let tx = self.read()?;
        if let Some(batch) = tx.batch(batch_id)? {
            return http::message_response(&BatchStateMessage {
                batch_id: batch.batch_id.as_bytes().to_owned(),
                state: BatchState::Committed,
                snapshot_seq: Some(batch.snapshot_seq.get()),
                base_seq_after: Some(batch.base_seq_after.get()),
                dir_version_after: Some(batch.dir_version_after),
                manifest_hash: batch.manifest_hash,
                dir_path: batch.dir_path,
            });
        }
        let Some(upload) = tx.upload(batch_id)? else {
            return Err(Fault::detail(ErrorCode::BatchNotFound, "batch not found"));
        };
        let state = match upload.state {
            UploadState::Aborted => BatchState::Aborted,
            _ => BatchState::Open,
        };
        http::message_response(&BatchStateMessage {
            batch_id: upload.batch_id.as_bytes().to_owned(),
            state,
            snapshot_seq: None,
            base_seq_after: None,
            dir_version_after: None,
            manifest_hash: upload.manifest_hash,
            dir_path: upload.dir_path,
        })
    }
}

fn full_signature(
    file: &crate::mmap::proto::SignatureFile,
    record: &FileRecord,
    block_size: u32,
) -> FileSignature {
    FileSignature {
        name: file.name.clone(),
        ino: record.ino,
        size: record.size,
        file_root: record.file_root,
        state: SignatureState::Full,
        block_size,
        block_count: 0,
        blocks: Vec::new(),
    }
}

fn read_block(
    tx: &ReadTx,
    record: &FileRecord,
    index: u32,
    block_size: u32,
) -> Result<Vec<u8>, Fault> {
    let offset = u64::from(index) * u64::from(block_size);
    if offset >= record.size {
        return Err(Fault::detail(
            ErrorCode::Internal,
            "signature block is out of range",
        ));
    }
    let len = u64::from(block_size).min(record.size - offset);
    read_range(tx, record, offset, len)
}

fn typed_attrs(attrs: &crate::mmap::proto::DirAttrs) -> Result<DirAttrs, Fault> {
    Ok(DirAttrs {
        mode: attrs.mode,
        uid: attrs.uid,
        gid: attrs.gid,
        mtime_ns: i64::try_from(attrs.mtime_ns)
            .map_err(|_| Fault::detail(ErrorCode::ManifestInvalid, "mtime overflows i64"))?,
    })
}

fn unexpired_locks<T: MmTx>(tx: &T) -> Result<Vec<LockRecord>, Fault> {
    let now = now_ms();
    let mut stmt = tx.conn().prepare(
        "SELECT dir_path, dir_ino, lock_id, owner_client, expires_at_ms
         FROM mm_locks WHERE namespace = ?1 AND expires_at_ms >= ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![tx.namespace(), now], |row| {
        let ino: Vec<u8> = row.get(1)?;
        let lock: Vec<u8> = row.get(2)?;
        let owner: Vec<u8> = row.get(3)?;
        Ok((
            row.get::<_, String>(0)?,
            ino,
            lock,
            owner,
            row.get::<_, i64>(4)?,
        ))
    })?;
    let mut locks = Vec::new();
    for row in rows {
        let (dir_path, ino, lock, owner, expires) = row?;
        let ino = <[u8; 16]>::try_from(ino)
            .map_err(|_| Fault::detail(ErrorCode::Internal, "lock ino is not 16 bytes"))?;
        let lock = <[u8; 16]>::try_from(lock)
            .map_err(|_| Fault::detail(ErrorCode::Internal, "lock id is not 16 bytes"))?;
        let owner = <[u8; 16]>::try_from(owner)
            .map_err(|_| Fault::detail(ErrorCode::Internal, "lock owner is not 16 bytes"))?;
        locks.push(LockRecord {
            lock_id: LockId::from_bytes(lock),
            dir_path,
            dir_ino: ino,
            owner_client: owner,
            owner_session: [0u8; 16],
            base_epoch: 1,
            base_seq: DirSeq::ZERO,
            batch_id: None,
            expires_at_ms: expires,
            created_at_ms: 0,
            renewed_at_ms: 0,
            progress_bytes: 0,
        });
    }
    Ok(locks)
}

/// A client inode is namespace-unique, not merely direct-entry unique.
///
/// Reusing the inode of a file in another directory, or of an ancestor
/// directory, would overwrite a row that this batch does not own.
fn check_provided_inos<T: MmTx>(
    tx: &T,
    entries: &[crate::mmap::proto::Entry],
    current: &[FileRecord],
) -> Result<(), Fault> {
    for entry in entries {
        let Some(ino) = entry.ino else {
            continue;
        };
        if matches!(
            entry.op,
            crate::mmap::proto::EntryOp::Delete | crate::mmap::proto::EntryOp::DirRemove
        ) {
            continue;
        }
        let owned = current.iter().any(|record| {
            record.ino == ino
                && (record.name == entry.name
                    || entry.from_name.as_deref() == Some(record.name.as_str()))
        });
        if owned {
            continue;
        }
        let exists: bool = tx.conn().query_row(
            "SELECT EXISTS(
               SELECT 1 FROM mm_files WHERE namespace = ?1 AND ino = ?2
               UNION
               SELECT 1 FROM mm_dirs WHERE namespace = ?1 AND ino = ?2
             )",
            rusqlite::params![tx.namespace(), ino.as_slice()],
            |row| row.get(0),
        )?;
        if exists {
            return Err(Fault::ino_conflict());
        }
    }
    Ok(())
}

fn batch_result(batch: &BatchRecord) -> UploadResult {
    UploadResult {
        snapshot_seq: batch.snapshot_seq.get(),
        epoch: batch.base_epoch,
        base_seq_after: batch.base_seq_after.get(),
        dir_version_after: batch.dir_version_after,
        batch_id: *batch.batch_id.as_bytes(),
        entry_count: batch.entry_count,
        bytes: batch.bytes,
        committed_at_ms: u64::try_from(batch.committed_at_ms).unwrap_or(0),
    }
}

/// One file reconstructed into the spool.
#[derive(Debug)]
struct Rebuilt {
    path: PathBuf,
    size: u64,
    content_hash: Hash,
    file_root: Hash,
    chunks: Vec<ChunkRef>,
}

#[allow(clippy::too_many_arguments)]
fn reconstruct(
    tx: ReadTx,
    spool: &Spool,
    batch_id: BatchId,
    dir_ino: Ino,
    entries: &[ManifestEntry],
    mode: UploadMode,
    payload: &Path,
    db_path: PathBuf,
    namespace: String,
    lock_id: LockId,
) -> Result<HashMap<usize, Rebuilt>, Fault> {
    let file = File::open(payload)?;
    let mut instructions = InstructionReader::new(BufReader::new(file));
    let mut groups: Vec<Vec<Step>> = (0..entries.len()).map(|_| Vec::new()).collect();
    let mut finished = vec![false; entries.len()];
    let mut saw_end = false;

    while let Some(instruction) = instructions
        .next_instruction()
        .map_err(|error| Fault::instruction(error.to_string()))?
    {
        match instruction {
            CommitStep::EndBatch => {
                saw_end = true;
                break;
            }
            CommitStep::EndFile { file_index } => {
                let index = usize::try_from(file_index)
                    .map_err(|_| Fault::instruction("file index is too large"))?;
                let entry = entries
                    .get(index)
                    .ok_or_else(|| Fault::instruction("file index is outside the manifest"))?;
                if entry.kind != EntryKind::File {
                    return Err(Fault::instruction("END_FILE names a non-file entry"));
                }
                if finished[index] {
                    return Err(Fault::instruction("two instruction groups for one file"));
                }
                finished[index] = true;
            }
            CommitStep::Copy {
                file_index,
                block_index,
                strong,
            } => {
                let index = entry_index(entries, file_index)?;
                if finished[index] {
                    return Err(Fault::instruction("COPY after END_FILE"));
                }
                if mode == UploadMode::Full {
                    return Err(Fault::instruction("full mode forbids COPY"));
                }
                groups[index].push(Step::Copy {
                    block_index,
                    strong,
                });
            }
            CommitStep::Literal { file_index, len } => {
                let index = entry_index(entries, file_index)?;
                if finished[index] {
                    return Err(Fault::instruction("LITERAL after END_FILE"));
                }
                // `read_literal` performs one underlying read; a literal
                // larger than the BufReader's remaining window needs the
                // looping helper.
                let mut bytes = Vec::with_capacity(len as usize);
                let copied = instructions
                    .copy_literal(&mut bytes)
                    .map_err(|error| Fault::instruction(error.to_string()))?;
                if copied != len || bytes.len() != len as usize {
                    return Err(Fault::instruction("literal is truncated"));
                }
                groups[index].push(Step::Literal(bytes));
            }
            CommitStep::Unchanged {
                file_index,
                content_hash,
            } => {
                let index = entry_index(entries, file_index)?;
                if finished[index] {
                    return Err(Fault::instruction("UNCHANGED after END_FILE"));
                }
                groups[index].push(Step::Unchanged(content_hash));
            }
        }
    }
    instructions
        .finish()
        .map_err(|error| Fault::instruction(error.to_string()))?;
    if !saw_end {
        return Err(Fault::instruction("missing END_BATCH"));
    }

    for (index, entry) in entries.iter().enumerate() {
        if entry.op.is_delete() {
            if finished[index] || !groups[index].is_empty() {
                return Err(Fault::instruction("instructions for a deleted entry"));
            }
            continue;
        }
        if entry.kind == EntryKind::File && !finished[index] {
            return Err(Fault::instruction("manifest file has no instruction group"));
        }
        if entry.kind != EntryKind::File && !groups[index].is_empty() {
            return Err(Fault::instruction("instructions for a non-file entry"));
        }
    }

    let mut rebuilt = HashMap::new();
    let mut renewer = ProgressRenewer::new(db_path, namespace, lock_id, batch_id);
    for (index, entry) in entries.iter().enumerate() {
        if entry.kind != EntryKind::File {
            continue;
        }
        let source = source_for(&tx, dir_ino, entry)?;
        match entry.op {
            EntryOp::Keep | EntryOp::Rename => {
                let Some(record) = source else {
                    return Err(Fault::instruction("unchanged file has no base"));
                };
                if groups[index].len() != 1 {
                    return Err(Fault::instruction(
                        "KEEP/RENAME needs exactly one UNCHANGED step",
                    ));
                }
                let Step::Unchanged(hash) = groups[index][0] else {
                    return Err(Fault::instruction(
                        "KEEP/RENAME needs exactly one UNCHANGED step",
                    ));
                };
                if record.content_hash != Some(hash)
                    || entry.content_hash.is_some_and(|expected| expected != hash)
                    || record.size != entry.size
                    || record.file_root != entry.file_root
                {
                    return Err(Fault::hash_mismatch(
                        entry.content_hash.unwrap_or(hash),
                        hash,
                    ));
                }
            }
            EntryOp::Put => {
                let output = spool.file_path(batch_id, index);
                let rebuilt_file = rebuild_one(
                    &tx,
                    entry,
                    source.as_ref(),
                    &groups[index],
                    &output,
                    mode,
                    &mut renewer,
                )?;
                rebuilt.insert(index, rebuilt_file);
            }
            _ => {}
        }
    }
    Ok(rebuilt)
}

fn entry_index(entries: &[ManifestEntry], file_index: u32) -> Result<usize, Fault> {
    let index =
        usize::try_from(file_index).map_err(|_| Fault::instruction("file index is too large"))?;
    let entry = entries
        .get(index)
        .ok_or_else(|| Fault::instruction("file index is outside the manifest"))?;
    if entry.kind != EntryKind::File {
        return Err(Fault::instruction("instruction names a non-file entry"));
    }
    Ok(index)
}

fn source_for(
    tx: &ReadTx,
    dir_ino: Ino,
    entry: &ManifestEntry,
) -> Result<Option<FileRecord>, Fault> {
    let record = match entry.op {
        EntryOp::Rename | EntryOp::DirRename => {
            let from = entry
                .from_name
                .as_deref()
                .ok_or_else(|| Fault::instruction("rename lacks from_name"))?;
            tx.file_by_name(dir_ino, from)?
        }
        EntryOp::Keep => tx.file(entry.ino)?,
        EntryOp::Put => tx.file_by_name(dir_ino, &entry.name)?,
        _ => None,
    };
    Ok(record.filter(|record| record.kind == EntryKind::File))
}

#[derive(Debug)]
enum Step {
    Copy { block_index: u32, strong: [u8; 16] },
    Literal(Vec<u8>),
    Unchanged([u8; 32]),
}

/// Extends the upload lease while a large commit is being reconstructed.
///
/// The commit already extended the lease to five minutes before starting.
/// This renewer adds the protocol's progress rule: after 8 MiB of rebuilt
/// bytes or 15 seconds, whichever comes first, the lease is pushed out again.
/// Small batches never open the extra connection.
struct ProgressRenewer {
    db_path: PathBuf,
    namespace: String,
    lock_id: LockId,
    batch_id: BatchId,
    last: Instant,
    next_bytes: u64,
    db: Option<MmDb>,
}

impl ProgressRenewer {
    const INTERVAL: Duration = Duration::from_secs(15);

    fn new(db_path: PathBuf, namespace: String, lock_id: LockId, batch_id: BatchId) -> Self {
        Self {
            db_path,
            namespace,
            lock_id,
            batch_id,
            last: Instant::now(),
            next_bytes: RENEW_PROGRESS_BYTES,
            db: None,
        }
    }

    fn note(&mut self, total: u64) {
        if total < self.next_bytes && self.last.elapsed() < Self::INTERVAL {
            return;
        }
        self.last = Instant::now();
        self.next_bytes = total.saturating_add(RENEW_PROGRESS_BYTES);
        if self.db.is_none() {
            match MmDb::open(
                &self.db_path,
                crate::mmap::types::MmRole::Server,
                &self.namespace,
            ) {
                Ok(db) => self.db = Some(db),
                Err(error) => {
                    tracing::warn!(%error, "cannot open the commit renewal connection");
                    return;
                }
            }
        }
        let Some(db) = self.db.as_mut() else {
            return;
        };
        let Ok(tx) = db.write() else {
            self.db = None;
            return;
        };
        let expires =
            now_ms().saturating_add(i64::try_from(COMMIT_LOCK_EXTENSION_MS).unwrap_or(i64::MAX));
        let _ = tx.renew_lock(self.lock_id, expires, total);
        let _ = tx.update_upload_progress(self.batch_id, total, expires);
        if tx.commit().is_err() {
            self.db = None;
        }
    }
}

fn rebuild_one(
    tx: &ReadTx,
    entry: &ManifestEntry,
    base: Option<&FileRecord>,
    steps: &[Step],
    output: &Path,
    mode: UploadMode,
    renewer: &mut ProgressRenewer,
) -> Result<Rebuilt, Fault> {
    let file = File::create(output)?;
    let mut writer = BufWriter::new(file);
    let mut hasher = blake3::Hasher::new();
    let mut chunker = Chunker::default();
    let base_size = base.map(|record| record.size).unwrap_or(0);
    let block_size = block_size_for(base_size);
    let block_count = block_count_for(base_size, block_size);
    let mut written = 0u64;
    if steps.iter().any(|step| matches!(step, Step::Unchanged(_))) && steps.len() != 1 {
        return Err(Fault::instruction(
            "UNCHANGED must be the only step for a file",
        ));
    }

    for step in steps {
        match step {
            Step::Literal(bytes) => {
                if bytes.len() as u64 > crate::mmap::proto::MAX_LITERAL as u64 {
                    return Err(Fault::instruction("literal is too large"));
                }
                write_hashed(
                    &mut writer,
                    &mut hasher,
                    &mut chunker,
                    &mut written,
                    renewer,
                    bytes,
                )?;
            }
            Step::Copy {
                block_index,
                strong,
            } => {
                let Some(record) = base else {
                    return Err(Fault::instruction("COPY without a base file"));
                };
                if mode == UploadMode::Full {
                    return Err(Fault::instruction("full mode forbids COPY"));
                }
                if u64::from(*block_index) >= block_count {
                    return Err(Fault::instruction("COPY block is outside the base file"));
                }
                let offset = u64::from(*block_index) * u64::from(block_size);
                let len = u64::from(block_size).min(base_size - offset);
                let bytes = read_range(tx, record, offset, len)?;
                if strong128(&bytes) != *strong {
                    return Err(Fault::hash_mismatch(
                        entry.content_hash.unwrap_or([0u8; 32]),
                        *blake3::hash(&bytes).as_bytes(),
                    ));
                }
                write_hashed(
                    &mut writer,
                    &mut hasher,
                    &mut chunker,
                    &mut written,
                    renewer,
                    &bytes,
                )?;
            }
            Step::Unchanged(hash) => {
                let Some(record) = base else {
                    return Err(Fault::instruction("UNCHANGED without a base file"));
                };
                if record.content_hash != Some(*hash) {
                    return Err(Fault::hash_mismatch(
                        *hash,
                        record.content_hash.unwrap_or([0u8; 32]),
                    ));
                }
                copy_base(
                    tx,
                    record,
                    &mut writer,
                    &mut hasher,
                    &mut chunker,
                    &mut written,
                    renewer,
                )?;
            }
        }
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);

    let content_hash = *hasher.finalize().as_bytes();
    let chunks = chunker.finish();
    let file_root = base::file_root(EntryKind::File, None, &chunks);
    if content_hash
        != entry
            .content_hash
            .ok_or_else(|| Fault::instruction("PUT file lacks content_hash"))?
    {
        return Err(Fault::hash_mismatch(
            entry.content_hash.unwrap_or([0u8; 32]),
            content_hash,
        ));
    }
    if written != entry.size {
        return Err(Fault::size_mismatch(entry.size, written));
    }
    if file_root != entry.file_root {
        return Err(Fault::hash_mismatch(entry.file_root, file_root));
    }
    Ok(Rebuilt {
        path: output.to_path_buf(),
        size: entry.size,
        content_hash,
        file_root,
        chunks,
    })
}

fn write_hashed<W: Write>(
    writer: &mut W,
    hasher: &mut blake3::Hasher,
    chunker: &mut Chunker,
    written: &mut u64,
    renewer: &mut ProgressRenewer,
    bytes: &[u8],
) -> Result<(), Fault> {
    writer.write_all(bytes)?;
    hasher.update(bytes);
    chunker.update(bytes);
    *written = written.saturating_add(bytes.len() as u64);
    renewer.note(*written);
    Ok(())
}

fn copy_base<W: Write>(
    tx: &ReadTx,
    record: &FileRecord,
    writer: &mut W,
    hasher: &mut blake3::Hasher,
    chunker: &mut Chunker,
    written: &mut u64,
    renewer: &mut ProgressRenewer,
) -> Result<(), Fault> {
    let chunks = tx.version_chunks(record.ino, record.version)?;
    let mut total = 0u64;
    for chunk in chunks {
        let data = tx
            .chunk(chunk.hash)?
            .ok_or_else(|| Fault::detail(ErrorCode::Internal, "base chunk is missing"))?;
        if data.len() != chunk.len as usize {
            return Err(Fault::detail(
                ErrorCode::Internal,
                "base chunk length differs",
            ));
        }
        write_hashed(writer, hasher, chunker, written, renewer, &data)?;
        total = total.saturating_add(data.len() as u64);
    }
    if total != record.size {
        return Err(Fault::detail(
            ErrorCode::Internal,
            "base file is incomplete",
        ));
    }
    Ok(())
}

#[derive(Default)]
struct Chunker {
    buffer: Vec<u8>,
    next: u32,
    chunks: Vec<ChunkRef>,
}

impl Chunker {
    fn update(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let remaining = 65_536 - self.buffer.len();
            let take = remaining.min(bytes.len());
            self.buffer.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.buffer.len() == 65_536 {
                self.flush();
            }
        }
    }

    fn flush(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        let hash = *blake3::hash(&self.buffer).as_bytes();
        self.chunks.push(ChunkRef {
            chunk_no: self.next,
            hash,
            offset: u64::from(self.next) * 65_536,
            len: self.buffer.len() as u32,
        });
        self.next += 1;
        self.buffer.clear();
    }

    fn finish(mut self) -> Vec<ChunkRef> {
        self.flush();
        self.chunks
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_commit(
    db: &mut MmDb,
    request: &UploadCommit,
    batch_id: BatchId,
    lock_id: LockId,
    session: SessionInfo,
    entries: &[ManifestEntry],
    dir_attrs: &DirAttrs,
    rebuilt: &HashMap<usize, Rebuilt>,
) -> Result<UploadResult, Fault> {
    let tx = db.write()?;
    if let Some(batch) = tx.batch(batch_id)? {
        if batch.manifest_hash != request.manifest_hash {
            return Err(Fault::detail(
                ErrorCode::BatchConflict,
                "batch id carries a different manifest",
            ));
        }
        let result = batch_result(&batch);
        tx.commit()?;
        return Ok(result);
    }
    let Some(upload) = tx.upload(batch_id)? else {
        return Err(Fault::detail(ErrorCode::BatchNotFound, "batch not found"));
    };
    if upload.state == UploadState::Aborted {
        return Err(Fault::detail(ErrorCode::BatchAborted, "batch is aborted"));
    }
    if upload.lock_id != lock_id {
        return Err(Fault::lock_lost("batch belongs to another lock"));
    }
    let lock = check_lock(&tx, lock_id, session, &upload.dir_path)?;
    if lock.base_epoch != upload.base_epoch || lock.base_seq != upload.base_seq {
        return Err(Fault::lock_lost("lock base differs from the upload base"));
    }
    let Some(dir) = tx.dir_by_path(&upload.dir_path)? else {
        return Err(Fault::detail(ErrorCode::DirNotFound, "directory not found"));
    };
    if request.epoch != upload.base_epoch
        || request.base_seq != upload.base_seq.get()
        || request.dir_version != upload.dir_version
        || tx.epoch()? != request.epoch
        || dir.base.dir_version != upload.dir_version
        || dir.base.dir_seq != upload.base_seq
    {
        return Err(Fault::base_changed(&dir, tx.mm_seq()?, request.base_seq));
    }

    let now = now_ms();
    let new_seq = tx.next_mm_seq()?;
    let current = tx.files(dir.ino)?;
    let final_entries = final_entries(entries, &current, rebuilt)?;
    let manifest = Manifest::new(final_entries.clone())
        .map_err(|error| Fault::detail(ErrorCode::ManifestInvalid, error.to_string()))?;
    let dir_version_after = base::dir_version(tx.namespace(), dir.ino, dir_attrs, &final_entries);
    let base_seq_after = DirSeq::new(dir.base.dir_seq.get() + 1);

    apply_tree(
        &tx,
        &dir,
        &current,
        entries,
        &final_entries,
        rebuilt,
        &new_seq,
        now,
    )?;

    let mut parent = dir.clone();
    parent.attrs = *dir_attrs;
    parent.base = MmBase::new(dir.base.epoch, base_seq_after, dir_version_after);
    parent.phase = Phase::Ready;
    parent.updated_at_ms = now;
    tx.put_dir(&parent)?;
    tx.set_dir_snapshot(dir.ino, new_seq)?;
    tx.replace_base_manifest(dir.ino, &manifest)?;

    let bytes: u64 = rebuilt.values().map(|file| file.size).sum();
    let batch = BatchRecord {
        batch_id,
        dir_path: dir.path.clone(),
        dir_ino: dir.ino,
        base_epoch: dir.base.epoch,
        base_seq: dir.base.dir_seq,
        base_seq_after,
        snapshot_seq: new_seq,
        dir_version_before: dir.base.dir_version,
        dir_version_after,
        manifest_hash: request.manifest_hash,
        client_id: session.client_id,
        entry_count: u32::try_from(final_entries.len())
            .map_err(|_| Fault::detail(ErrorCode::TooManyEntries, "entry count overflows"))?,
        bytes,
        committed_at_ms: now,
    };
    if !tx.put_batch(&batch)? {
        return Err(Fault::detail(
            ErrorCode::BatchConflict,
            "batch was inserted concurrently",
        ));
    }
    tx.delete_lock(lock_id)?;
    tx.delete_upload(batch_id)?;
    recompute_refcounts(&tx)?;
    tx.commit()?;
    Ok(batch_result(&batch))
}

fn final_entries(
    entries: &[ManifestEntry],
    current: &[FileRecord],
    rebuilt: &HashMap<usize, Rebuilt>,
) -> Result<Vec<ManifestEntry>, Fault> {
    let by_ino: HashMap<Ino, &FileRecord> =
        current.iter().map(|record| (record.ino, record)).collect();
    let mut final_entries = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        if entry.op.is_delete() {
            continue;
        }
        let mut final_entry = entry.clone();
        final_entry.op = EntryOp::Keep;
        final_entry.from_name = None;
        match entry.kind {
            EntryKind::File => {
                if entry.op == EntryOp::Put {
                    let file = rebuilt.get(&index).ok_or_else(|| {
                        Fault::detail(ErrorCode::Internal, "rebuilt file is missing")
                    })?;
                    if file.content_hash
                        != entry
                            .content_hash
                            .ok_or_else(|| Fault::instruction("PUT lacks content_hash"))?
                    {
                        return Err(Fault::hash_mismatch(
                            entry.content_hash.unwrap_or([0u8; 32]),
                            file.content_hash,
                        ));
                    }
                    if file.size != entry.size {
                        return Err(Fault::size_mismatch(entry.size, file.size));
                    }
                    if file.file_root != entry.file_root {
                        return Err(Fault::hash_mismatch(entry.file_root, file.file_root));
                    }
                    final_entry.size = file.size;
                    final_entry.content_hash = Some(file.content_hash);
                    final_entry.file_root = file.file_root;
                } else {
                    let record = by_ino.get(&entry.ino).copied().ok_or_else(|| {
                        Fault::detail(ErrorCode::ManifestInvalid, "KEEP/RENAME file is absent")
                    })?;
                    final_entry.size = record.size;
                    final_entry.file_root = record.file_root;
                    final_entry.content_hash = record.content_hash;
                    final_entry.target = record.target.clone();
                }
            }
            EntryKind::Symlink => {
                let target = entry.target.as_deref().ok_or_else(|| {
                    Fault::detail(ErrorCode::ManifestInvalid, "symlink lacks a target")
                })?;
                final_entry.size = target.len() as u64;
                final_entry.file_root = base::symlink_root(target);
                final_entry.content_hash = None;
            }
            EntryKind::Dir => {
                final_entry.size = 0;
                final_entry.file_root = base::dir_root();
                final_entry.content_hash = None;
                final_entry.target = None;
            }
        }
        final_entries.push(final_entry);
    }
    Ok(final_entries)
}

#[allow(clippy::too_many_arguments)]
fn apply_tree(
    tx: &WriteTx<'_>,
    dir: &DirRecord,
    current: &[FileRecord],
    entries: &[ManifestEntry],
    final_entries: &[ManifestEntry],
    rebuilt: &HashMap<usize, Rebuilt>,
    new_seq: &MmSeq,
    now: i64,
) -> Result<(), Fault> {
    let final_by_ino: HashMap<Ino, &ManifestEntry> = final_entries
        .iter()
        .map(|entry| (entry.ino, entry))
        .collect();
    let op_by_name: HashMap<&str, EntryOp> = entries
        .iter()
        .map(|entry| (entry.name.as_str(), entry.op))
        .collect();
    let source_name: HashMap<&str, &str> = entries
        .iter()
        .filter_map(|entry| {
            entry
                .from_name
                .as_deref()
                .map(|from| (entry.name.as_str(), from))
        })
        .collect();

    let mut taken: HashSet<String> = current
        .iter()
        .map(|record| record.name.clone())
        .chain(final_entries.iter().map(|entry| entry.name.clone()))
        .collect();
    let mut temp_by_ino: HashMap<Ino, String> = HashMap::new();

    // A directory rename moves a whole subtree. A lock on either subtree
    // blocks the batch with 423, even though the parent directory itself is
    // the one being written.
    for entry in entries {
        if entry.op != EntryOp::DirRename {
            continue;
        }
        let Some(from) = entry.from_name.as_deref() else {
            continue;
        };
        let source = child_path(&dir.path, from);
        let target = child_path(&dir.path, &entry.name);
        for path in [&source, &target] {
            if let Some(lock) = lock_below(tx, path)? {
                return Err(Fault::lock_held(&lock));
            }
        }
    }

    // Phase A: remove everything that is not final, and move every rename
    // source out of the way so target names are free.
    for record in current {
        let Some(final_entry) = final_by_ino.get(&record.ino) else {
            delete_current(tx, dir, record, now)?;
            continue;
        };
        if final_entry.name == record.name {
            continue;
        }
        let temp = temp_name(&record.ino, &mut taken);
        move_to_temp(tx, dir, record, &temp, now)?;
        temp_by_ino.insert(record.ino, temp);
    }

    // Phase B: write every final entry.
    for final_entry in final_entries {
        let op = op_by_name
            .get(final_entry.name.as_str())
            .copied()
            .unwrap_or(EntryOp::Keep);
        let source_name = source_name.get(final_entry.name.as_str()).copied();
        let source = match op {
            EntryOp::Rename | EntryOp::DirRename => source_name
                .and_then(|name| current.iter().find(|record| record.name == name).cloned()),
            EntryOp::Put => current
                .iter()
                .find(|record| record.name == final_entry.name && record.ino == final_entry.ino)
                .cloned(),
            EntryOp::DirAdd => None,
            _ => current
                .iter()
                .find(|record| record.name == final_entry.name)
                .cloned(),
        };
        let index = entries
            .iter()
            .position(|entry| entry.name == final_entry.name);
        persist_entry(
            tx,
            dir,
            final_entry,
            op,
            source.as_ref(),
            temp_by_ino.get(&final_entry.ino).map(String::as_str),
            index.and_then(|index| rebuilt.get(&index)),
            new_seq,
            now,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn persist_entry(
    tx: &WriteTx<'_>,
    dir: &DirRecord,
    entry: &ManifestEntry,
    op: EntryOp,
    source: Option<&FileRecord>,
    temp_name: Option<&str>,
    rebuilt: Option<&Rebuilt>,
    new_seq: &MmSeq,
    now: i64,
) -> Result<(), Fault> {
    let attrs = attrs_of(entry);
    let final_path = child_path(&dir.path, &entry.name);
    if entry.kind == EntryKind::Dir {
        let created_at = match source {
            Some(record) if record.kind == EntryKind::Dir => {
                let Some(child) = tx.dir(entry.ino)? else {
                    return Err(Fault::detail(
                        ErrorCode::ManifestInvalid,
                        "directory row is missing",
                    ));
                };
                if let Some(temp) = temp_name {
                    let temp_path = child_path(&dir.path, temp);
                    move_dir_subtree(tx, &temp_path, &final_path, now)?;
                }
                let attrs_changed = child.attrs != attrs;
                if attrs_changed {
                    let records = tx.files(child.ino)?;
                    let child_entries: Vec<ManifestEntry> = records
                        .iter()
                        .map(|record| record.manifest_entry(EntryOp::Keep))
                        .collect();
                    let version =
                        base::dir_version(tx.namespace(), child.ino, &attrs, &child_entries);
                    let updated = DirRecord {
                        path: final_path.clone(),
                        base: MmBase::new(
                            child.base.epoch,
                            DirSeq::new(child.base.dir_seq.get() + 1),
                            version,
                        ),
                        attrs,
                        updated_at_ms: now,
                        ..child
                    };
                    tx.put_dir(&updated)?;
                    tx.set_dir_snapshot(entry.ino, *new_seq)?;
                } else if temp_name.is_some() || child.path != final_path {
                    let updated = DirRecord {
                        path: final_path.clone(),
                        updated_at_ms: now,
                        ..child
                    };
                    tx.put_dir(&updated)?;
                }
                record.created_at_ms
            }
            _ => {
                let version = base::dir_version(tx.namespace(), entry.ino, &attrs, &[]);
                let child = DirRecord {
                    ino: entry.ino,
                    path: final_path.clone(),
                    base: MmBase::new(tx.epoch()?, DirSeq::new(1), version),
                    phase: Phase::Ready,
                    attrs,
                    deleted: false,
                    created_at_ms: now,
                    updated_at_ms: now,
                };
                tx.put_dir(&child)?;
                tx.clear_base(entry.ino)?;
                now
            }
        };
        let record = FileRecord {
            ino: entry.ino,
            dir_ino: dir.ino,
            name: entry.name.clone(),
            kind: EntryKind::Dir,
            attrs,
            size: 0,
            file_root: base::dir_root(),
            content_hash: None,
            target: None,
            version: 0,
            deleted: false,
            created_at_ms: source
                .map(|record| record.created_at_ms)
                .unwrap_or(created_at),
            updated_at_ms: now,
        };
        tx.put_file(&record)?;
        return Ok(());
    }

    let version = match entry.kind {
        EntryKind::File => match op {
            EntryOp::Put => source.map(|record| record.version + 1).unwrap_or(1),
            _ => source.map(|record| record.version).unwrap_or(1),
        },
        EntryKind::Symlink => source.map(|record| record.version.max(1)).unwrap_or(1),
        EntryKind::Dir => 0,
    };
    let record = FileRecord {
        ino: entry.ino,
        dir_ino: dir.ino,
        name: entry.name.clone(),
        kind: entry.kind,
        attrs,
        size: entry.size,
        file_root: entry.file_root,
        content_hash: entry.content_hash,
        target: entry.target.clone(),
        version,
        deleted: false,
        created_at_ms: source.map(|record| record.created_at_ms).unwrap_or(now),
        updated_at_ms: now,
    };
    tx.put_file(&record)?;
    if entry.kind == EntryKind::File && op == EntryOp::Put {
        let Some(rebuilt) = rebuilt else {
            return Err(Fault::detail(
                ErrorCode::Internal,
                "rebuilt content is missing",
            ));
        };
        write_version(tx, &record, rebuilt, now)?;
    }
    Ok(())
}

fn attrs_of(entry: &ManifestEntry) -> DirAttrs {
    DirAttrs {
        mode: entry.mode,
        uid: entry.uid,
        gid: entry.gid,
        mtime_ns: entry.mtime_ns,
    }
}

fn write_version(
    tx: &WriteTx<'_>,
    record: &FileRecord,
    rebuilt: &Rebuilt,
    now: i64,
) -> Result<(), Fault> {
    let file = File::open(&rebuilt.path)?;
    let mut reader = BufReader::new(file);
    let mut buffer = vec![0u8; 65_536];
    for chunk in &rebuilt.chunks {
        let len = chunk.len as usize;
        reader.read_exact(&mut buffer[..len])?;
        if *blake3::hash(&buffer[..len]).as_bytes() != chunk.hash {
            return Err(Fault::detail(
                ErrorCode::Internal,
                "spooled file changed after reconstruction",
            ));
        }
        tx.put_chunk(chunk.hash, &buffer[..len])?;
    }
    let mut extra = [0u8; 1];
    if reader.read(&mut extra)? != 0 {
        return Err(Fault::size_mismatch(record.size, record.size + 1));
    }
    tx.put_version(&VersionRecord {
        ino: record.ino,
        version: record.version,
        size: record.size,
        file_root: record.file_root,
        content_hash: record.content_hash.unwrap_or([0u8; 32]),
        chunk_count: u32::try_from(rebuilt.chunks.len())
            .map_err(|_| Fault::detail(ErrorCode::TooManyEntries, "chunk count overflows"))?,
        created_at_ms: now,
    })?;
    tx.put_version_chunks(record.ino, record.version, &rebuilt.chunks)?;
    Ok(())
}

fn delete_current(
    tx: &WriteTx<'_>,
    dir: &DirRecord,
    record: &FileRecord,
    now: i64,
) -> Result<(), Fault> {
    if record.kind == EntryKind::Dir {
        let path = child_path(&dir.path, &record.name);
        if let Some(lock) = lock_below(tx, &path)? {
            return Err(Fault::lock_held(&lock));
        }
        if !tx.files(record.ino)?.is_empty() {
            return Err(Fault::detail(
                ErrorCode::DirNotEmpty,
                format!("directory {} is not empty", record.name),
            ));
        }
        tx.delete_file(record.ino)?;
        tx.delete_dir(record.ino)?;
        let _ = now;
        Ok(())
    } else {
        tx.delete_file(record.ino)?;
        Ok(())
    }
}

fn move_to_temp(
    tx: &WriteTx<'_>,
    dir: &DirRecord,
    record: &FileRecord,
    temp: &str,
    now: i64,
) -> Result<(), Fault> {
    if record.kind == EntryKind::Dir {
        let old_path = child_path(&dir.path, &record.name);
        let new_path = child_path(&dir.path, temp);
        move_dir_subtree(tx, &old_path, &new_path, now)?;
        let mut row = record.clone();
        row.name = temp.to_owned();
        row.updated_at_ms = now;
        tx.put_file(&row)?;
    } else {
        let mut row = record.clone();
        row.name = temp.to_owned();
        row.updated_at_ms = now;
        tx.put_file(&row)?;
    }
    Ok(())
}

fn temp_name(ino: &Ino, taken: &mut HashSet<String>) -> String {
    let base = format!(".sm-tmp-{}", hex::encode(ino));
    let mut name = base.clone();
    let mut serial = 0u32;
    while taken.contains(&name) {
        serial += 1;
        name = format!("{base}-{serial}");
    }
    taken.insert(name.clone());
    name
}

fn move_dir_subtree(tx: &WriteTx<'_>, old: &str, new: &str, now: i64) -> Result<(), Fault> {
    if old == new {
        return Ok(());
    }
    if path_is_within(new, old) {
        return Err(Fault::detail(
            ErrorCode::ManifestInvalid,
            "directory rename target is inside its source",
        ));
    }
    for table in ["mm_dirs", "mm_dir_versions"] {
        let column = if table == "mm_dirs" {
            "path"
        } else {
            "dir_path"
        };
        tx.conn().execute(
            &format!(
                "UPDATE {table} SET {column} = ?1 || substr({column}, length(?2) + 1),
                 updated_at_ms = ?3
                 WHERE namespace = ?4
                   AND substr({column}, 1, length(?2)) = ?2
                   AND (length({column}) = length(?2)
                        OR substr({column}, length(?2) + 1, 1) = '/')"
            ),
            rusqlite::params![new, old, now, tx.namespace()],
        )?;
    }
    Ok(())
}

fn lock_below<T: MmTx>(tx: &T, path: &str) -> Result<Option<LockRecord>, Fault> {
    let now = now_ms();
    let mut stmt = tx.conn().prepare(
        "SELECT dir_path, dir_ino, lock_id, owner_client, expires_at_ms
         FROM mm_locks
         WHERE namespace = ?1 AND expires_at_ms >= ?2
           AND (dir_path = ?3
                OR (substr(dir_path, 1, length(?3)) = ?3
                    AND substr(dir_path, length(?3) + 1, 1) = '/'))
         LIMIT 1",
    )?;
    let mut rows = stmt.query(rusqlite::params![tx.namespace(), now, path])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let dir_path: String = row.get(0)?;
    let ino: Vec<u8> = row.get(1)?;
    let lock: Vec<u8> = row.get(2)?;
    let owner: Vec<u8> = row.get(3)?;
    let expires: i64 = row.get(4)?;
    Ok(Some(LockRecord {
        lock_id: LockId::from_bytes(
            <[u8; 16]>::try_from(lock)
                .map_err(|_| Fault::detail(ErrorCode::Internal, "lock id is not 16 bytes"))?,
        ),
        dir_path,
        dir_ino: <[u8; 16]>::try_from(ino)
            .map_err(|_| Fault::detail(ErrorCode::Internal, "lock ino is not 16 bytes"))?,
        owner_client: <[u8; 16]>::try_from(owner)
            .map_err(|_| Fault::detail(ErrorCode::Internal, "lock owner is not 16 bytes"))?,
        owner_session: [0u8; 16],
        base_epoch: 1,
        base_seq: DirSeq::ZERO,
        batch_id: None,
        expires_at_ms: expires,
        created_at_ms: 0,
        renewed_at_ms: 0,
        progress_bytes: 0,
    }))
}

fn recompute_refcounts(tx: &WriteTx<'_>) -> Result<(), Fault> {
    tx.conn().execute(
        "UPDATE mm_chunks SET refcount =
           (SELECT COUNT(*) FROM mm_version_chunks vc WHERE vc.chunk_hash = mm_chunks.hash)",
        [],
    )?;
    tx.conn()
        .execute("DELETE FROM mm_chunks WHERE refcount = 0", [])?;
    Ok(())
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn chunker_splits_on_the_storage_grid() {
        let mut chunker = Chunker::default();
        chunker.update(&vec![1u8; 70_000]);
        let chunks = chunker.finish();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len, 65_536);
        assert_eq!(chunks[1].len, 4_464);
        assert_eq!(chunks[1].offset, 65_536);
    }

    #[test]
    fn temp_names_do_not_collide() {
        let mut taken = HashSet::new();
        let first = temp_name(&[1; 16], &mut taken);
        let second = temp_name(&[1; 16], &mut taken);
        assert_ne!(first, second);
    }
}
