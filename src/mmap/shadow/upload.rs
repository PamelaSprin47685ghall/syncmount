//! The `fsync` chain.
//!
//! ```text
//! FUSE_WRITE -> shadow pwrite -> dirty generation
//! FUSE_FSYNC -> freeze dirty files into staging -> acquire lease
//!            -> revalidate base -> full manifest -> signatures
//!            -> upload commit -> local base/metadata commit
//! ```
//!
//! A failure keeps the dirty generation, removes staging, releases the lease
//! best-effort, and returns a conflict or an I/O error. The next `fsync`
//! starts from the then-current base. Nothing is retried inside one call.

use std::collections::HashMap;
use std::fs::File;
use std::io::Cursor;
use std::path::PathBuf;

use crate::mmap::manifest::Manifest;
use crate::mmap::rsync::{Instruction, decode_from, delta_to};
use crate::mmap::types::{
    BatchId, BatchRecord, EntryKind, EntryOp, FileRecord, Hash, Ino, LockId, ManifestEntry,
    VersionRecord,
};

use super::content::{self, ContentHashes};
use super::db::UploadPhase;
use super::remote::{
    LockRequest, LockResponse, SignatureFile, SignatureFilePlan, SignaturesRequest, UploadBegin,
    UploadCommit, UploadFile, UploadRequest, UploadResponse,
};
use super::{Shadow, ShadowError, now_ms};

/// One frozen file used by one upload.
#[derive(Clone, Debug)]
struct SnapshotFile {
    path: PathBuf,
    hashes: ContentHashes,
}

impl Shadow {
    /// Flush one file's directory to the server.
    ///
    /// `flush` and `release` never call this. A successful return means the
    /// server committed the batch and the local base/uploaded generation was
    /// durably recorded.
    pub fn fsync(&self, fuse_ino: u64, fh: Option<u64>) -> Result<(), ShadowError> {
        let (dir_ino, _ino, _version) = self.resolve_handle(fuse_ino, fh)?;
        self.ensure_dir(dir_ino, false)?;
        let dir = self.db.shadow_dir(dir_ino)?.ok_or(ShadowError::NotFound)?;
        if dir.clean() {
            return Ok(());
        }
        let slot = self.slot(dir_ino);
        let _upload = super::lock(&slot.upload);
        let dir = self.db.shadow_dir(dir_ino)?.ok_or(ShadowError::NotFound)?;
        if dir.clean() {
            return Ok(());
        }
        self.flush_dir_locked(dir)
    }

    /// Flush one directory even when no individual file triggered it.
    pub fn fsyncdir(&self, fuse_ino: u64) -> Result<(), ShadowError> {
        let row = self.db.fuse_row(fuse_ino)?.ok_or(ShadowError::NotFound)?;
        if row.kind != EntryKind::Dir {
            return Err(ShadowError::NotDir);
        }
        let dir = self.db.shadow_dir(row.ino)?.ok_or(ShadowError::NotFound)?;
        if dir.clean() {
            return Ok(());
        }
        let slot = self.slot(row.ino);
        let _upload = super::lock(&slot.upload);
        let dir = self.db.shadow_dir(row.ino)?.ok_or(ShadowError::NotFound)?;
        if dir.clean() {
            return Ok(());
        }
        self.flush_dir_locked(dir)
    }

    fn resolve_handle(
        &self,
        fuse_ino: u64,
        fh: Option<u64>,
    ) -> Result<(Ino, Ino, u64), ShadowError> {
        if let Some(handle) = fh.and_then(|id| self.handle(id)) {
            return Ok((handle.dir_ino, handle.ino, handle.version));
        }
        let row = self.db.fuse_row(fuse_ino)?.ok_or(ShadowError::NotFound)?;
        let file = self.db.file(row.ino)?.ok_or(ShadowError::NotFound)?;
        Ok((file.dir_ino, row.ino, row.version))
    }

    fn flush_dir_locked(&self, mut dir: super::ShadowDir) -> Result<(), ShadowError> {
        if dir.local_only {
            // A locally created child directory has no server row yet. Its
            // parent struct changes must commit first; the next fsync retries.
            return Err(ShadowError::Conflict);
        }
        if dir.batch_id.is_some() {
            // A batch from an earlier attempt may have committed after its
            // answer was lost. Adopt that result before starting another
            // batch; a transport failure keeps the state for the next fsync.
            match self.reconcile_batch(&dir) {
                Ok(_) => {}
                Err(ShadowError::Remote(super::RemoteError::Unsupported(_))) => {
                    // The remote has no batch endpoint; a new batch is the
                    // only way forward.
                    self.db.clear_batch(dir.record.ino, UploadPhase::Dirty)?;
                }
                Err(error) => return Err(error),
            }
            dir = self
                .db
                .shadow_dir(dir.record.ino)?
                .ok_or(ShadowError::NotFound)?;
            if dir.clean() {
                return Ok(());
            }
        }
        let snapshot_gen = dir.dirty_gen;
        let batch_id = BatchId::new_random();
        let staging = self.layout.create_staging(&dir.record.ino, batch_id)?;
        self.db.set_upload_phase(
            dir.record.ino,
            UploadPhase::Snapshotting,
            Some(batch_id),
            None,
        )?;

        let result = self.snapshot_and_upload(&dir, batch_id, snapshot_gen, &staging);
        match &result {
            Ok(()) => {
                let _ = std::fs::remove_dir_all(&staging);
            }
            Err(error) => {
                let _ = std::fs::remove_dir_all(&staging);
                let phase = match error {
                    ShadowError::Remote(remote) if remote.is_conflict() => {
                        if matches!(
                            remote,
                            super::RemoteError::LockHeld { .. }
                                | super::RemoteError::LockLost { .. }
                                | super::RemoteError::LockExpired
                        ) {
                            UploadPhase::Locked
                        } else {
                            UploadPhase::Conflict
                        }
                    }
                    _ => UploadPhase::Dirty,
                };
                let _ = self
                    .db
                    .set_upload_phase(dir.record.ino, phase, Some(batch_id), None);
            }
        }
        result
    }

    fn snapshot_and_upload(
        &self,
        dir: &super::ShadowDir,
        batch_id: BatchId,
        snapshot_gen: u64,
        staging: &std::path::Path,
    ) -> Result<(), ShadowError> {
        let mut snapshots: HashMap<Ino, SnapshotFile> = HashMap::new();
        let mut snapshotted_records: HashMap<Ino, FileRecord> = HashMap::new();
        let mut snapshotted_generation: HashMap<Ino, u64> = HashMap::new();
        let mut snapshot_gen = snapshot_gen;
        // Freeze every generation that existed when the fsync started. A new
        // write during the copy has a newer generation; one late pass catches
        // files created between the fetch and the freeze. Eight passes bound
        // a pathological writer; a still-newer generation falls through to
        // the next fsync.
        for _ in 0..8 {
            let files = self.db.files(dir.record.ino)?;
            let mut changed = false;
            for file in &files {
                if file.kind != EntryKind::File {
                    continue;
                }
                let Some(version) = self.db.shadow_version(file.ino, file.version)? else {
                    continue;
                };
                let previous = snapshotted_generation.get(&file.ino).copied().unwrap_or(0);
                if version.dirty_gen == 0 || version.dirty_gen <= previous {
                    continue;
                }
                // Writes and snapshotting take the same per-version mutex. A
                // write that arrives during this copy gets a newer dirty
                // generation and is uploaded by the next fsync.
                let lock = self.version_lock(file.ino, file.version);
                let _guard = super::lock(&lock);
                let mut source = self.layout.open_object(&file.ino, file.version)?;
                let path = staging.join(format!("{}.v{}", super::hex16(&file.ino), file.version));
                let hashes = content::copy_and_hash(&mut source, &path)?;
                let mut record = file.clone();
                record.size = hashes.size;
                record.file_root = hashes.file_root;
                record.content_hash = Some(hashes.content_hash);
                self.db.put_file(&record)?;
                self.db.set_version_snapshot(
                    file.ino,
                    file.version,
                    hashes.size,
                    hashes.file_root,
                    hashes.content_hash,
                    record.attrs.mtime_ns,
                )?;
                self.db.put_version(&VersionRecord {
                    ino: file.ino,
                    version: file.version,
                    size: hashes.size,
                    file_root: hashes.file_root,
                    content_hash: hashes.content_hash,
                    chunk_count: u32::try_from(hashes.size.div_ceil(65_536)).unwrap_or(u32::MAX),
                    created_at_ms: now_ms(),
                })?;
                snapshotted_generation.insert(file.ino, version.dirty_gen);
                snapshot_gen = snapshot_gen.max(version.dirty_gen);
                snapshotted_records.insert(file.ino, record);
                snapshots.insert(file.ino, SnapshotFile { path, hashes });
                changed = true;
            }
            if !changed {
                break;
            }
        }

        // The generation boundary must survive a crash: a committed batch
        // adopts exactly the dirty versions it contained, never a write that
        // arrived after the snapshot.
        self.db.set_snapshot_gen(dir.record.ino, snapshot_gen)?;

        self.db
            .set_upload_phase(dir.record.ino, UploadPhase::Locking, Some(batch_id), None)?;
        let lock = match self.remote.lock(&LockRequest::Acquire {
            dir_path: dir.record.path.clone(),
            dir_ino: dir.record.ino,
            base: dir.record.base,
            batch_id: Some(batch_id),
            ttl_ms: 60_000,
        }) {
            Ok(LockResponse::Granted(granted)) => granted,
            Ok(other) => {
                return Err(ShadowError::Remote(super::RemoteError::Internal(format!(
                    "unexpected lock response: {other:?}"
                ))));
            }
            Err(error) => {
                let _ = self.db.set_upload_phase(
                    dir.record.ino,
                    UploadPhase::Locked,
                    Some(batch_id),
                    None,
                );
                return Err(error.into());
            }
        };
        self.db.set_upload_phase(
            dir.record.ino,
            UploadPhase::Uploading,
            Some(batch_id),
            Some(lock.lock_id),
        )?;

        let result = self.upload_with_lock(
            dir,
            batch_id,
            lock.lock_id,
            snapshot_gen,
            &snapshots,
            &snapshotted_records,
        );
        let _ = self.remote.lock(&LockRequest::Release {
            lock_id: lock.lock_id,
        });
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = self.db.set_upload_phase(
                    dir.record.ino,
                    if error.is_remote_conflict() {
                        UploadPhase::Conflict
                    } else {
                        UploadPhase::Dirty
                    },
                    Some(batch_id),
                    None,
                );
                Err(error)
            }
        }
    }

    fn upload_with_lock(
        &self,
        dir: &super::ShadowDir,
        batch_id: BatchId,
        lock_id: LockId,
        snapshot_gen: u64,
        snapshots: &HashMap<Ino, SnapshotFile>,
        snapshotted_records: &HashMap<Ino, FileRecord>,
    ) -> Result<(), ShadowError> {
        // Revalidate after the lease: the base the commit will CAS against
        // must be this directory's current one, not the one observed before
        // the snapshot.
        let base_before = self
            .db
            .shadow_dir(dir.record.ino)?
            .ok_or(ShadowError::NotFound)?
            .record
            .base;
        let checkout = self.remote.checkout(&super::CheckoutRequest {
            dir_path: dir.record.path.clone(),
            dir_ino: dir.record.ino,
            if_base: Some(base_before),
            if_snapshot: Some(dir.snapshot_seq),
            bodies: false,
        })?;
        match checkout {
            super::CheckoutOutcome::NotModified { .. } => {}
            super::CheckoutOutcome::Snapshot(snapshot) => {
                self.apply_snapshot(snapshot, false)?;
            }
        }
        let after = self
            .db
            .shadow_dir(dir.record.ino)?
            .ok_or(ShadowError::NotFound)?;

        let files = self.db.files(dir.record.ino)?;
        let mut current: Vec<ManifestEntry> = Vec::with_capacity(files.len());
        for file in &files {
            let record = snapshotted_records
                .get(&file.ino)
                .cloned()
                .unwrap_or_else(|| file.clone());
            current.push(record.manifest_entry(EntryOp::Keep));
        }
        let current_manifest = Manifest::new(current)?;
        let base_entries = self.db.base_manifest(dir.record.ino)?;
        let manifest = Manifest::diff(&base_entries, current_manifest.entries())?;
        let manifest_hash = manifest.hash();

        // BEGIN must precede SIGNATURES: the server only has a batch (and
        // therefore a stable base for block signatures) after BEGIN. Asking
        // first makes an HTTP client fall back to reading the whole base file,
        // which turns one 4 KiB delta into a full download.
        let _plan = self.remote.upload(&UploadRequest::Begin(UploadBegin {
            batch_id,
            dir_path: dir.record.path.clone(),
            dir_ino: dir.record.ino,
            base: after.record.base,
            manifest: manifest.entries().to_vec(),
        }))?;

        // Signatures are requested only for content that differs from base.
        let mut signature_files = Vec::new();
        for entry in manifest.entries() {
            if entry.op == EntryOp::Put && entry.kind == EntryKind::File {
                signature_files.push(SignatureFile {
                    name: entry.name.clone(),
                    ino: entry.ino,
                    size: entry.size,
                    file_root: entry.file_root,
                });
            }
        }
        let mut signatures: HashMap<Ino, SignatureFilePlan> = HashMap::new();
        if !signature_files.is_empty() {
            let response = self.remote.signatures(&SignaturesRequest {
                dir_path: dir.record.path.clone(),
                dir_ino: dir.record.ino,
                base: after.record.base,
                files: signature_files,
            })?;
            for plan in response.files {
                signatures.insert(plan.ino, plan);
            }
        }

        let mut upload_files = Vec::new();
        let mut bytes = 0u64;
        for (index, entry) in manifest.entries().iter().enumerate() {
            if entry.kind == EntryKind::Dir {
                continue;
            }
            let Some(file) = files.iter().find(|file| file.ino == entry.ino) else {
                continue;
            };
            let keep = entry.op == EntryOp::Keep;
            let Some(snapshot) = snapshots.get(&entry.ino) else {
                upload_files.push(UploadFile {
                    manifest_index: index as u32,
                    ino: entry.ino,
                    version: file.version,
                    size: entry.size,
                    file_root: entry.file_root,
                    content_hash: entry.content_hash.unwrap_or_else(|| {
                        *blake3::hash(entry.target.as_deref().unwrap_or_default()).as_bytes()
                    }),
                    source: None,
                    instructions: Vec::new(),
                    unchanged: true,
                });
                continue;
            };
            let plan = signatures.get(&entry.ino);
            let (instructions, unchanged) = if keep {
                (Vec::new(), true)
            } else if plan.is_some_and(|plan| plan.unchanged) {
                (
                    vec![
                        Instruction::Unchanged {
                            file: index as u32,
                            content_hash: snapshot.hashes.content_hash,
                        },
                        Instruction::EndFile { file: index as u32 },
                        Instruction::EndBatch,
                    ],
                    true,
                )
            } else {
                let instructions = build_instructions(
                    &snapshot.path,
                    plan.and_then(|plan| plan.signature.as_ref()),
                    snapshot.hashes.content_hash,
                    index as u32,
                )?;
                (instructions, false)
            };
            bytes = bytes.saturating_add(snapshot.hashes.size);
            upload_files.push(UploadFile {
                manifest_index: index as u32,
                ino: entry.ino,
                version: file.version,
                size: snapshot.hashes.size,
                file_root: snapshot.hashes.file_root,
                content_hash: snapshot.hashes.content_hash,
                source: Some(snapshot.path.clone()),
                instructions,
                unchanged,
            });
        }

        let committed = match self.remote.upload(&UploadRequest::Commit(UploadCommit {
            batch_id,
            lock_id,
            dir_path: dir.record.path.clone(),
            dir_ino: dir.record.ino,
            base: after.record.base,
            manifest: manifest.entries().to_vec(),
            files: upload_files,
            bytes,
        }))? {
            UploadResponse::Committed(result) => result,
            other => {
                return Err(ShadowError::Remote(super::RemoteError::Internal(format!(
                    "unexpected commit response: {other:?}"
                ))));
            }
        };

        let client_id = self.db.client_id()?;
        let batch_record = BatchRecord {
            batch_id,
            dir_path: dir.record.path.clone(),
            dir_ino: dir.record.ino,
            base_epoch: after.record.base.epoch,
            base_seq: after.record.base.dir_seq,
            base_seq_after: committed.base.dir_seq,
            snapshot_seq: committed.snapshot_seq,
            dir_version_before: after.record.base.dir_version,
            dir_version_after: committed.dir_version,
            manifest_hash,
            client_id,
            entry_count: u32::try_from(manifest.len()).unwrap_or(u32::MAX),
            bytes: committed.bytes,
            committed_at_ms: now_ms(),
        };
        let valid_until_ms =
            now_ms().saturating_add(i64::try_from(self.ttl.as_millis()).unwrap_or(i64::MAX));
        self.db.publish_committed(
            dir.record.ino,
            committed.base,
            committed.snapshot_seq,
            snapshot_gen,
            valid_until_ms,
            Some(&batch_record),
        )?;
        Ok(())
    }
}

impl ShadowError {
    fn is_remote_conflict(&self) -> bool {
        matches!(self, ShadowError::Remote(remote) if remote.is_conflict())
    }
}

fn build_instructions(
    path: &std::path::Path,
    signature: Option<&crate::mmap::rsync::Signature>,
    content_hash: Hash,
    file_index: u32,
) -> Result<Vec<Instruction>, ShadowError> {
    let Some(signature) = signature else {
        return literal_instructions(path, file_index);
    };
    let file = File::open(path)?;
    let mut encoded = Vec::new();
    match delta_to(file, signature, &mut encoded) {
        Ok(_) => {
            let instructions = decode_from(Cursor::new(encoded))?;
            Ok(remap(instructions, file_index))
        }
        Err(_) => literal_instructions(path, file_index),
    }
    .map(|mut instructions| {
        if instructions.is_empty() {
            instructions.push(Instruction::Unchanged {
                file: file_index,
                content_hash,
            });
            instructions.push(Instruction::EndFile { file: file_index });
            instructions.push(Instruction::EndBatch);
        }
        instructions
    })
}

fn literal_instructions(
    path: &std::path::Path,
    file_index: u32,
) -> Result<Vec<Instruction>, ShadowError> {
    use std::io::Read as _;

    let mut file = File::open(path)?;
    let mut buffer = vec![0u8; 64 * 1024];
    let mut instructions = Vec::new();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        instructions.push(Instruction::Literal {
            file: file_index,
            bytes: buffer[..read].to_vec(),
        });
    }
    instructions.push(Instruction::EndFile { file: file_index });
    instructions.push(Instruction::EndBatch);
    Ok(instructions)
}

pub(super) fn remap(instructions: Vec<Instruction>, file_index: u32) -> Vec<Instruction> {
    instructions
        .into_iter()
        .map(|instruction| match instruction {
            Instruction::Literal { bytes, .. } => Instruction::Literal {
                file: file_index,
                bytes,
            },
            Instruction::Copy {
                block,
                offset,
                len,
                strong,
                ..
            } => Instruction::Copy {
                file: file_index,
                block,
                offset,
                len,
                strong,
            },
            Instruction::Unchanged { content_hash, .. } => Instruction::Unchanged {
                file: file_index,
                content_hash,
            },
            Instruction::EndFile { .. } => Instruction::EndFile { file: file_index },
            Instruction::EndBatch => Instruction::EndBatch,
        })
        .collect()
}
