//! Endpoint implementations and the `MmRemote` boundary.
//!
//! Every public endpoint maps one `MmRemote` request to one SMM1 message. The
//! three special cases live here, next to the endpoint they repair:
//!
//! * an upload `BEGIN` or `COMMIT` whose response was lost asks
//!   `GET batch/{id}` and adopts a committed batch or resends an open one;
//! * `signatures` normally uses the server endpoint, but the shadow asks for
//!   signatures before it has begun a batch. In that order the server has no
//!   upload row to validate, so the client computes the same rsync signature
//!   from the checked-out base instead of returning a fake full plan;
//! * `lock/acquire` carries the session id, so its meta is built inside the
//!   authenticated retry loop.

use std::io::Cursor;

use crate::mmap::base;
use crate::mmap::proto::{
    BatchState, BatchStateMessage, Checkout, DirVersion, Entry as WireEntry, ErrorCode,
    FileData as WireFileData, FileRead, FileSignature, Kind, LockAcquire, LockGranted, LockRelease,
    LockRenew, SignatureRequest, SignatureState, Signatures, Snapshot, UploadAbort, UploadBegin,
    UploadCommit, UploadMode, UploadPlan, UploadResult,
};
use crate::mmap::rsync::{
    BlockSignature, MAX_BLOCKS, Signature, block_count_for, block_size_for, sign,
};
use crate::mmap::shadow::{
    CheckoutBody, CheckoutEntry, CheckoutOutcome, CheckoutRequest, CheckoutSnapshot, FileData,
    FileReadRequest, GrantedLock, LockRequest, LockResponse, RemoteError, SignatureFilePlan,
    SignaturesRequest, SignaturesResponse, UploadBegin as RemoteBegin,
    UploadCommit as RemoteCommit, UploadPlan as RemotePlan, UploadResponse,
    UploadResult as RemoteResult,
};
use crate::mmap::types::{BatchId, DirAttrs, DirSeq, EntryKind, Hash, Ino, LockId, MmBase, MmSeq};

use super::MmHttpClient;
use super::http::{WireFailure, WireResponse};
use super::wire::{self, CommitPlan};

/// A batch state as reported by `GET batch/{id}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchStatus {
    /// Batch id.
    pub batch_id: BatchId,
    /// `OPEN`, `COMMITTED` or `ABORTED`.
    pub state: BatchState,
    /// New global sequence, when committed.
    pub snapshot_seq: Option<MmSeq>,
    /// New per-directory sequence, when committed.
    pub base_seq_after: Option<DirSeq>,
    /// New directory version, when committed.
    pub dir_version_after: Option<Hash>,
    /// Manifest hash the batch was begun with.
    pub manifest_hash: Hash,
    /// Directory the batch writes.
    pub dir_path: String,
}

/// A directory version as reported by `GET version`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirVersionInfo {
    /// Database epoch.
    pub epoch: u64,
    /// Global sequence observed with the version.
    pub snapshot_seq: MmSeq,
    /// Base triple.
    pub base: MmBase,
    /// Directory path.
    pub dir_path: String,
}

fn encode<M: crate::mmap::proto::Message>(message: &M) -> Result<Vec<u8>, WireFailure> {
    message.encode_meta().map_err(WireFailure::from_proto)
}

fn mm_base(epoch: u64, dir_seq: u64, dir_version: Hash) -> MmBase {
    MmBase::new(epoch, DirSeq::new(dir_seq), dir_version)
}

fn detail(error: &crate::mmap::proto::ErrorBody) -> String {
    error
        .detail
        .clone()
        .unwrap_or_else(|| error.code.as_str().to_owned())
}

/// Map one wire failure onto the shadow's stable classification.
pub(super) fn map_failure(failure: WireFailure) -> RemoteError {
    match failure {
        WireFailure::Transport(message) => RemoteError::Io(message),
        WireFailure::Protocol(message) => RemoteError::Internal(message),
        WireFailure::Status { body, .. } => match body.code {
            ErrorCode::AuthFailed | ErrorCode::SessionExpired => RemoteError::Unauthenticated,
            ErrorCode::DirNotFound | ErrorCode::NotADirectory | ErrorCode::BatchNotFound => {
                RemoteError::NotFound
            }
            ErrorCode::BaseChanged => {
                let epoch = body.epoch.unwrap_or(0);
                let dir_seq = body.base_seq.unwrap_or(0);
                let dir_version = body.dir_version.unwrap_or([0u8; 32]);
                RemoteError::BaseChanged {
                    current: mm_base(epoch, dir_seq, dir_version),
                    snapshot_seq: MmSeq::new(body.snapshot_seq.unwrap_or(0)),
                }
            }
            ErrorCode::SignatureStale | ErrorCode::FileChanged => RemoteError::SignatureStale,
            ErrorCode::ManifestIncomplete => RemoteError::ManifestIncomplete {
                missing: body.missing.clone(),
            },
            ErrorCode::HashMismatch | ErrorCode::SizeMismatch => RemoteError::HashMismatch {
                name: detail(&body),
                retry_full: body.retry_full,
            },
            ErrorCode::BatchConflict
            | ErrorCode::BatchCommitted
            | ErrorCode::BatchAborted
            | ErrorCode::InoConflict
            | ErrorCode::NameConflict => RemoteError::BatchConflict,
            ErrorCode::DirNotEmpty => RemoteError::DirNotEmpty(detail(&body)),
            ErrorCode::LockHeld => RemoteError::LockHeld {
                owner: body.owner_client.map(hex::encode).unwrap_or_default(),
                expires_at_ms: body.expires_at_ms.unwrap_or(0),
                retry_after_ms: body.retry_after_ms.unwrap_or(0),
            },
            ErrorCode::LockLost => RemoteError::LockLost {
                reason: body.reason.clone().unwrap_or_else(|| detail(&body)),
            },
            ErrorCode::LockExpired => RemoteError::LockExpired,
            ErrorCode::TooLarge | ErrorCode::TooManyEntries | ErrorCode::TooManyBlocks => {
                RemoteError::TooLarge(detail(&body))
            }
            ErrorCode::ManifestInvalid
            | ErrorCode::InstructionMismatch
            | ErrorCode::BadRequest
            | ErrorCode::PathInvalid => {
                RemoteError::Internal(format!("{}: {}", body.code.as_str(), detail(&body)))
            }
            ErrorCode::Internal => RemoteError::Internal(detail(&body)),
            ErrorCode::Busy | ErrorCode::StoreGone | ErrorCode::NoSpace => {
                RemoteError::Internal(format!("{}: {}", body.code.as_str(), detail(&body)))
            }
        },
    }
}

fn missing_headers(response: &WireResponse) -> WireFailure {
    WireFailure::Protocol(format!(
        "304 response lacks its base headers: {:?}",
        response.headers
    ))
}

fn header_u64(response: &WireResponse, name: &str) -> Result<u64, WireFailure> {
    response
        .headers
        .get(name)
        .ok_or_else(|| missing_headers(response))?
        .parse::<u64>()
        .map_err(|_| WireFailure::Protocol(format!("bad `{name}` header")))
}

fn header_hash(response: &WireResponse, name: &str) -> Result<Hash, WireFailure> {
    let value = response
        .headers
        .get(name)
        .ok_or_else(|| missing_headers(response))?;
    let bytes =
        hex::decode(value).map_err(|_| WireFailure::Protocol(format!("bad `{name}` header")))?;
    bytes
        .try_into()
        .map_err(|_| WireFailure::Protocol(format!("bad `{name}` header length")))
}

impl MmHttpClient {
    // -----------------------------------------------------------------
    // checkout / read
    // -----------------------------------------------------------------

    pub(super) fn checkout_endpoint(
        &self,
        request: &CheckoutRequest,
    ) -> Result<CheckoutOutcome, RemoteError> {
        let message = Checkout {
            namespace: self.config().namespace.wire_label().to_owned(),
            dir_path: request.dir_path.clone(),
            bodies: u8::from(request.bodies),
            if_dir_version: request.if_base.map(|base| base.dir_version),
            if_snapshot_seq: if request.if_base.is_none() {
                request.if_snapshot.map(MmSeq::get)
            } else {
                None
            },
        };
        let meta = encode(&message).map_err(map_failure)?;
        let response = self
            .call(
                "POST",
                "/mm/v1/checkout",
                Some((Kind::Checkout, &meta)),
                None,
            )
            .map_err(map_failure)?;
        if response.status == 304 {
            let base = mm_base(
                header_u64(&response, "x-sm-mm-epoch").map_err(map_failure)?,
                header_u64(&response, "x-sm-mm-base-seq").map_err(map_failure)?,
                header_hash(&response, "x-sm-mm-dir-version").map_err(map_failure)?,
            );
            let snapshot_seq =
                MmSeq::new(header_u64(&response, "x-sm-mm-snapshot-seq").map_err(map_failure)?);
            let cached = {
                let cache = self.cache();
                cache
                    .snapshots
                    .get(&request.dir_ino)
                    .map(|snapshot| (snapshot.attrs, snapshot.entries.clone()))
            };
            // Do not invent attributes for a directory that was never
            // checked out in this process. A later BEGIN would otherwise
            // upload a zeroed mtime; leaving the cache empty makes
            // `attrs_for_upload` fetch a full snapshot instead.
            if let Some((attrs, entries)) = cached {
                self.remember_snapshot(request.dir_ino, base, snapshot_seq, attrs, entries);
            }
            return Ok(CheckoutOutcome::NotModified { base, snapshot_seq });
        }
        if response.status != 200 {
            return Err(map_failure(response.into_failure()));
        }
        let snapshot: Snapshot = response.decode().map_err(map_failure)?;
        let outcome = self.snapshot_from_wire(&response, snapshot, request.bodies)?;
        Ok(CheckoutOutcome::Snapshot(outcome))
    }

    fn snapshot_from_wire(
        &self,
        response: &WireResponse,
        snapshot: Snapshot,
        with_bodies: bool,
    ) -> Result<CheckoutSnapshot, RemoteError> {
        let mut entries = Vec::with_capacity(snapshot.entries.len());
        for entry in snapshot.entries {
            entries.push(entry_from_wire(entry)?);
        }
        let attrs = DirAttrs {
            mode: snapshot.dir_attrs.mode,
            uid: snapshot.dir_attrs.uid,
            gid: snapshot.dir_attrs.gid,
            mtime_ns: i64::try_from(snapshot.dir_attrs.mtime_ns)
                .map_err(|_| RemoteError::Internal("directory mtime overflows i64".to_owned()))?,
        };
        let base = mm_base(snapshot.epoch, snapshot.base_seq, snapshot.dir_version);
        let snapshot_seq = MmSeq::new(snapshot.snapshot_seq);

        let mut bodies = Vec::new();
        if with_bodies {
            let payload = response.payload().map_err(map_failure)?;
            let mut cursor = 0usize;
            for entry in &entries {
                if entry.kind != EntryKind::File {
                    continue;
                }
                let size = usize::try_from(entry.size).map_err(|_| {
                    RemoteError::Internal("file size does not fit usize".to_owned())
                })?;
                let end = cursor
                    .checked_add(size)
                    .ok_or_else(|| RemoteError::Internal("checkout body overflows".to_owned()))?;
                if end > payload.len() {
                    return Err(RemoteError::Internal(format!(
                        "checkout body for {} is truncated",
                        entry.name
                    )));
                }
                let bytes = &payload[cursor..end];
                verify_content(entry, bytes)?;
                bodies.push(CheckoutBody {
                    ino: entry.ino,
                    bytes: bytes.to_vec(),
                });
                cursor = end;
            }
            if cursor != payload.len() {
                return Err(RemoteError::Internal(
                    "checkout payload carries bytes for no entry".to_owned(),
                ));
            }
        }

        self.remember_snapshot(snapshot.dir_ino, base, snapshot_seq, attrs, entries.clone());
        Ok(CheckoutSnapshot {
            dir_ino: snapshot.dir_ino,
            base,
            snapshot_seq,
            attrs,
            entries,
            bodies,
        })
    }

    pub(super) fn file_read_endpoint(
        &self,
        request: &FileReadRequest,
    ) -> Result<FileData, RemoteError> {
        let message = FileRead {
            namespace: self.config().namespace.wire_label().to_owned(),
            dir_path: request.dir_path.clone(),
            name: request.name.clone(),
            ino: request.ino,
            file_root: request.file_root,
            range_offset: request.offset,
            range_len: request.len,
        };
        let meta = encode(&message).map_err(map_failure)?;
        let response = self
            .call(
                "POST",
                "/mm/v1/file/read",
                Some((Kind::FileRead, &meta)),
                None,
            )
            .map_err(map_failure)?;
        if response.status != 200 {
            return Err(map_failure(response.into_failure()));
        }
        let data: WireFileData = response.decode().map_err(map_failure)?;
        let payload = response.payload().map_err(map_failure)?;
        if data.range_len as usize != payload.len() {
            return Err(RemoteError::Internal(
                "FILE_DATA length differs from the payload".to_owned(),
            ));
        }
        let hash = *blake3::hash(payload).as_bytes();
        if hash != data.range_hash {
            return Err(RemoteError::Internal(
                "FILE_DATA range hash does not match its bytes".to_owned(),
            ));
        }
        Ok(FileData {
            offset: data.range_offset,
            bytes: payload.to_vec(),
            range_hash: data.range_hash,
        })
    }

    // -----------------------------------------------------------------
    // signatures
    // -----------------------------------------------------------------

    pub(super) fn signatures_endpoint(
        &self,
        request: &SignaturesRequest,
    ) -> Result<SignaturesResponse, RemoteError> {
        if let Some((batch_id, lock_id)) = self.active_batch(request.dir_ino) {
            // A lease from an earlier fsync may still be cached after its
            // release failed. A signature request against it would fail
            // LOCK_LOST, so use the server only when this is the lock that
            // the shadow currently holds.
            if self.lock_for_dir(&request.dir_path) == Some(lock_id) {
                match self.signatures_remote(request, batch_id, lock_id) {
                    Ok(response) => return Ok(response),
                    // The shadow asks before BEGIN; the server cannot
                    // validate a batch that does not exist yet. Compute the
                    // same signature from the base it checked out instead of
                    // failing the fsync.
                    Err(RemoteError::NotFound) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        self.signatures_local(request)
    }

    fn signatures_remote(
        &self,
        request: &SignaturesRequest,
        batch_id: BatchId,
        lock_id: LockId,
    ) -> Result<SignaturesResponse, RemoteError> {
        let files = request
            .files
            .iter()
            .map(|file| crate::mmap::proto::SignatureFile {
                name: file.name.clone(),
                ino: Some(file.ino),
                size: file.size,
                local_file_root: file.file_root,
            })
            .collect();
        let message = SignatureRequest {
            namespace: self.config().namespace.wire_label().to_owned(),
            dir_path: request.dir_path.clone(),
            dir_ino: request.dir_ino,
            epoch: request.base.epoch,
            base_seq: request.base.dir_seq.get(),
            dir_version: request.base.dir_version,
            lock_id: *lock_id.as_bytes(),
            batch_id: *batch_id.as_bytes(),
            files,
        };
        let meta = encode(&message).map_err(map_failure)?;
        let response = self
            .call(
                "POST",
                "/mm/v1/signatures",
                Some((Kind::SignaturesReq, &meta)),
                None,
            )
            .map_err(map_failure)?;
        if response.status != 200 {
            return Err(map_failure(response.into_failure()));
        }
        let signatures: Signatures = response.decode().map_err(map_failure)?;
        if mm_base(
            signatures.epoch,
            signatures.base_seq,
            signatures.dir_version,
        ) != request.base
        {
            return Err(RemoteError::SignatureStale);
        }
        let mut plans = Vec::with_capacity(signatures.files.len());
        for file in signatures.files {
            plans.push(signature_plan_from_wire(file)?);
        }
        Ok(SignaturesResponse {
            base: request.base,
            files: plans,
        })
    }

    fn signatures_local(
        &self,
        request: &SignaturesRequest,
    ) -> Result<SignaturesResponse, RemoteError> {
        let base = self.base_snapshot(request)?;
        if base.base != request.base {
            return Err(RemoteError::SignatureStale);
        }
        let mut plans = Vec::with_capacity(request.files.len());
        for file in &request.files {
            let entry = base.entries.iter().find(|entry| entry.name == file.name);
            let Some(entry) = entry.filter(|entry| entry.kind == EntryKind::File) else {
                plans.push(SignatureFilePlan {
                    ino: file.ino,
                    unchanged: false,
                    signature: None,
                });
                continue;
            };
            if entry.file_root == file.file_root && entry.size == file.size {
                plans.push(SignatureFilePlan {
                    ino: file.ino,
                    unchanged: true,
                    signature: None,
                });
                continue;
            }
            let block_size = block_size_for(entry.size);
            if block_count_for(entry.size, block_size) > MAX_BLOCKS {
                plans.push(SignatureFilePlan {
                    ino: file.ino,
                    unchanged: false,
                    signature: None,
                });
                continue;
            }
            let bytes = self.read_base_file(&request.dir_path, request.dir_ino, entry)?;
            let signature = sign(Cursor::new(bytes), block_size).map_err(|error| {
                RemoteError::Internal(format!("cannot sign {}: {error}", entry.name))
            })?;
            plans.push(SignatureFilePlan {
                ino: file.ino,
                unchanged: false,
                signature: Some(signature),
            });
        }
        Ok(SignaturesResponse {
            base: base.base,
            files: plans,
        })
    }

    fn base_snapshot(&self, request: &SignaturesRequest) -> Result<CheckoutSnapshot, RemoteError> {
        if let Some((base, snapshot_seq, attrs, entries)) = self.snapshot(request.dir_ino) {
            if base == request.base {
                return Ok(CheckoutSnapshot {
                    dir_ino: request.dir_ino,
                    base,
                    snapshot_seq,
                    attrs,
                    entries,
                    bodies: Vec::new(),
                });
            }
        }
        let outcome = self.checkout_endpoint(&CheckoutRequest {
            dir_path: request.dir_path.clone(),
            dir_ino: request.dir_ino,
            if_base: None,
            if_snapshot: None,
            bodies: false,
        })?;
        match outcome {
            CheckoutOutcome::Snapshot(snapshot) => Ok(snapshot),
            CheckoutOutcome::NotModified { .. } => Err(RemoteError::Internal(
                "checkout unexpectedly returned 304 for a full request".to_owned(),
            )),
        }
    }

    fn read_base_file(
        &self,
        dir_path: &str,
        dir_ino: Ino,
        entry: &CheckoutEntry,
    ) -> Result<Vec<u8>, RemoteError> {
        const RANGE: u32 = 8 * 1024 * 1024;
        let mut out = Vec::with_capacity(usize::try_from(entry.size).unwrap_or(0));
        let mut offset = 0u64;
        while offset < entry.size {
            let len = u32::try_from((entry.size - offset).min(u64::from(RANGE))).unwrap_or(RANGE);
            let data = self.file_read_endpoint(&FileReadRequest {
                dir_path: dir_path.to_owned(),
                dir_ino,
                name: entry.name.clone(),
                ino: entry.ino,
                file_root: entry.file_root,
                offset,
                len,
            })?;
            if data.offset != offset {
                return Err(RemoteError::Internal(
                    "FILE_DATA returned an unexpected offset".to_owned(),
                ));
            }
            if data.bytes.is_empty() && offset < entry.size {
                return Err(RemoteError::Io(format!(
                    "{} ended before its declared size",
                    entry.name
                )));
            }
            offset = offset.saturating_add(data.bytes.len() as u64);
            out.extend_from_slice(&data.bytes);
        }
        Ok(out)
    }

    // -----------------------------------------------------------------
    // upload
    // -----------------------------------------------------------------

    pub(super) fn upload_begin(
        &self,
        request: &RemoteBegin,
    ) -> Result<UploadResponse, RemoteError> {
        let attrs = self.attrs_for_upload(&request.dir_path, request.dir_ino)?;
        let lock_id = self
            .lock_for_dir(&request.dir_path)
            .ok_or_else(|| RemoteError::Internal("upload begin has no acquired lock".to_owned()))?;
        let order = wire::sorted_indices(&request.manifest);
        let entries = order
            .iter()
            .map(|index| wire::wire_entry(&request.manifest[*index]))
            .collect::<Result<Vec<_>, _>>()?;
        let structural = order
            .iter()
            .map(|index| &request.manifest[*index])
            .filter(|entry| entry.kind == EntryKind::Dir)
            .map(wire::wire_entry)
            .collect::<Result<Vec<_>, _>>()?;
        let manifest_hash = wire::manifest_hash(&request.manifest)?;
        let message = UploadBegin {
            namespace: self.config().namespace.wire_label().to_owned(),
            dir_path: request.dir_path.clone(),
            dir_ino: request.dir_ino,
            epoch: request.base.epoch,
            base_seq: request.base.dir_seq.get(),
            dir_version: request.base.dir_version,
            batch_id: *request.batch_id.as_bytes(),
            lock_id: *lock_id.as_bytes(),
            client_id: self.config().client_id,
            manifest_hash,
            entries,
            structural,
            dir_attrs: wire::wire_attrs(&attrs)?,
            mode: UploadMode::Delta,
        };
        let meta = encode(&message).map_err(map_failure)?;
        match self.begin_once(&meta) {
            Ok(response) => {
                let plan: UploadPlan = response.decode().map_err(map_failure)?;
                self.remember_batch(request.dir_ino, request.batch_id, lock_id);
                Ok(UploadResponse::Plan(RemotePlan {
                    batch_id: BatchId::from_bytes(plan.batch_id),
                    base: mm_base(plan.epoch, plan.base_seq, plan.dir_version),
                    expires_at_ms: plan.lock_expires_at_ms,
                }))
            }
            Err(failure) if failure.is_status(ErrorCode::BatchCommitted) => {
                // Same batch id and manifest are already committed; COMMIT
                // will return the original result.
                self.remember_batch(request.dir_ino, request.batch_id, lock_id);
                Ok(UploadResponse::Plan(RemotePlan {
                    batch_id: request.batch_id,
                    base: request.base,
                    expires_at_ms: 0,
                }))
            }
            Err(WireFailure::Transport(first)) => {
                self.recover_begin(request, lock_id, manifest_hash, &meta, first)
            }
            Err(failure) => Err(map_failure(failure)),
        }
    }

    fn begin_once(&self, meta: &[u8]) -> Result<WireResponse, WireFailure> {
        let response = self.call(
            "POST",
            "/mm/v1/upload/begin",
            Some((Kind::UploadBegin, meta)),
            None,
        )?;
        if response.status != 200 {
            return Err(response.into_failure());
        }
        Ok(response)
    }

    fn recover_begin(
        &self,
        request: &RemoteBegin,
        lock_id: LockId,
        manifest_hash: Hash,
        meta: &[u8],
        first: String,
    ) -> Result<UploadResponse, RemoteError> {
        match self.batch_status_wire(request.batch_id) {
            Ok(status) => {
                if status.state == BatchState::Aborted || status.manifest_hash != manifest_hash {
                    return Err(RemoteError::BatchConflict);
                }
                self.remember_batch(request.dir_ino, request.batch_id, lock_id);
                Ok(UploadResponse::Plan(RemotePlan {
                    batch_id: request.batch_id,
                    base: request.base,
                    expires_at_ms: 0,
                }))
            }
            Err(WireFailure::Status { body, .. }) if body.code == ErrorCode::BatchNotFound => {
                match self.begin_once(meta) {
                    Ok(response) => {
                        let plan: UploadPlan = response.decode().map_err(map_failure)?;
                        self.remember_batch(request.dir_ino, request.batch_id, lock_id);
                        Ok(UploadResponse::Plan(RemotePlan {
                            batch_id: BatchId::from_bytes(plan.batch_id),
                            base: mm_base(plan.epoch, plan.base_seq, plan.dir_version),
                            expires_at_ms: plan.lock_expires_at_ms,
                        }))
                    }
                    Err(second) => Err(RemoteError::Io(format!(
                        "upload begin acknowledgement lost: {first}; retry: {}",
                        failure_text(&second)
                    ))),
                }
            }
            Err(other) => Err(RemoteError::Io(format!(
                "upload begin acknowledgement lost: {first}; status: {}",
                failure_text(&other)
            ))),
        }
    }

    pub(super) fn upload_commit(
        &self,
        request: &RemoteCommit,
    ) -> Result<UploadResponse, RemoteError> {
        let result = self.upload_commit_inner(request);
        if result.is_err() {
            // The next fsync uses a new lock and a new batch id. Leaving the
            // failed pair here would make a later signature request try a
            // dead server-side batch.
            self.forget_batch(request.batch_id);
        }
        result
    }

    fn upload_commit_inner(&self, request: &RemoteCommit) -> Result<UploadResponse, RemoteError> {
        let plan = CommitPlan::build(request)?;
        let manifest_hash = wire::manifest_hash(&request.manifest)?;
        let message = UploadCommit {
            namespace: self.config().namespace.wire_label().to_owned(),
            batch_id: *request.batch_id.as_bytes(),
            lock_id: *request.lock_id.as_bytes(),
            epoch: request.base.epoch,
            base_seq: request.base.dir_seq.get(),
            dir_version: request.base.dir_version,
            manifest_hash,
        };
        let meta = encode(&message).map_err(map_failure)?;
        match self.commit_once(&meta, &plan) {
            Ok(response) => {
                let result: UploadResult = response.decode().map_err(map_failure)?;
                self.forget_batch(request.batch_id);
                self.cache().snapshots.remove(&request.dir_ino);
                Ok(UploadResponse::Committed(remote_result(result)))
            }
            Err(WireFailure::Transport(first)) => self.recover_commit(request, &meta, &plan, first),
            Err(failure) => Err(map_failure(failure)),
        }
    }

    fn commit_once(&self, meta: &[u8], plan: &CommitPlan<'_>) -> Result<WireResponse, WireFailure> {
        let response = self.call(
            "POST",
            "/mm/v1/upload/commit",
            Some((Kind::UploadCommit, meta)),
            Some(plan),
        )?;
        if response.status != 200 {
            return Err(response.into_failure());
        }
        Ok(response)
    }

    fn recover_commit(
        &self,
        request: &RemoteCommit,
        meta: &[u8],
        plan: &CommitPlan<'_>,
        first: String,
    ) -> Result<UploadResponse, RemoteError> {
        match self.batch_status_wire(request.batch_id) {
            Ok(status) if status.state == BatchState::Committed => {
                Ok(UploadResponse::Committed(status_result(request, &status)?))
            }
            Ok(status) if status.state == BatchState::Open => match self.commit_once(meta, plan) {
                Ok(response) => {
                    let result: UploadResult = response.decode().map_err(map_failure)?;
                    self.forget_batch(request.batch_id);
                    self.cache().snapshots.remove(&request.dir_ino);
                    Ok(UploadResponse::Committed(remote_result(result)))
                }
                Err(WireFailure::Transport(second)) => {
                    match self.batch_status_wire(request.batch_id) {
                        Ok(status) if status.state == BatchState::Committed => {
                            Ok(UploadResponse::Committed(status_result(request, &status)?))
                        }
                        _ => Err(RemoteError::Io(format!(
                            "commit acknowledgement lost: {first}; retry: {second}"
                        ))),
                    }
                }
                Err(failure) => Err(map_failure(failure)),
            },
            Ok(_) => Err(RemoteError::BatchConflict),
            Err(WireFailure::Status { body, .. }) if body.code == ErrorCode::BatchNotFound => {
                Err(RemoteError::BatchConflict)
            }
            Err(other) => Err(RemoteError::Io(format!(
                "commit acknowledgement lost: {first}; status: {}",
                failure_text(&other)
            ))),
        }
    }

    pub(super) fn upload_abort(
        &self,
        request: &crate::mmap::shadow::UploadAbort,
    ) -> Result<UploadResponse, RemoteError> {
        let result = self.upload_abort_inner(request);
        if result.is_err() {
            self.forget_batch(request.batch_id);
        }
        result
    }

    fn upload_abort_inner(
        &self,
        request: &crate::mmap::shadow::UploadAbort,
    ) -> Result<UploadResponse, RemoteError> {
        let message = UploadAbort {
            batch_id: *request.batch_id.as_bytes(),
            lock_id: *request.lock_id.as_bytes(),
        };
        let meta = encode(&message).map_err(map_failure)?;
        match self.call(
            "POST",
            "/mm/v1/upload/abort",
            Some((Kind::UploadAbort, &meta)),
            None,
        ) {
            Ok(response) if response.status == 200 || response.status == 204 => {
                self.forget_batch(request.batch_id);
                Ok(UploadResponse::Aborted)
            }
            Ok(response) if response.status == 404 => {
                self.forget_batch(request.batch_id);
                Ok(UploadResponse::Aborted)
            }
            Ok(response) => Err(map_failure(response.into_failure())),
            Err(WireFailure::Transport(first)) => match self.batch_status_wire(request.batch_id) {
                Ok(status) if status.state == BatchState::Aborted => {
                    self.forget_batch(request.batch_id);
                    Ok(UploadResponse::Aborted)
                }
                Ok(status) => Err(RemoteError::Internal(format!(
                    "abort acknowledgement lost; batch is {:?}: {first}",
                    status.state
                ))),
                Err(WireFailure::Status { body, .. }) if body.code == ErrorCode::BatchNotFound => {
                    self.forget_batch(request.batch_id);
                    Ok(UploadResponse::Aborted)
                }
                Err(other) => Err(RemoteError::Io(format!(
                    "abort acknowledgement lost: {first}; status: {}",
                    failure_text(&other)
                ))),
            },
            Err(failure) => Err(map_failure(failure)),
        }
    }

    fn attrs_for_upload(&self, dir_path: &str, dir_ino: Ino) -> Result<DirAttrs, RemoteError> {
        if let Some(attrs) = self.dir_attrs(dir_ino) {
            return Ok(attrs);
        }
        let outcome = self.checkout_endpoint(&CheckoutRequest {
            dir_path: dir_path.to_owned(),
            dir_ino,
            if_base: None,
            if_snapshot: None,
            bodies: false,
        })?;
        match outcome {
            CheckoutOutcome::Snapshot(snapshot) => Ok(snapshot.attrs),
            CheckoutOutcome::NotModified { .. } => Err(RemoteError::Internal(
                "checkout unexpectedly returned 304 for a full request".to_owned(),
            )),
        }
    }

    // -----------------------------------------------------------------
    // locks
    // -----------------------------------------------------------------

    pub(super) fn lock_endpoint(&self, request: &LockRequest) -> Result<LockResponse, RemoteError> {
        match request {
            LockRequest::Acquire { dir_path, .. } => self.lock_acquire(dir_path),
            LockRequest::Renew {
                lock_id,
                progress_bytes,
                ..
            } => self.lock_renew(*lock_id, *progress_bytes),
            LockRequest::Release { lock_id } => self.lock_release(*lock_id),
        }
    }

    fn lock_acquire(&self, dir_path: &str) -> Result<LockResponse, RemoteError> {
        let namespace = self.config().namespace.wire_label().to_owned();
        let dir_path = dir_path.to_owned();
        let client_id = self.config().client_id;
        let reclaim = self.lock_for_dir(&dir_path);
        let response = self.call_with("POST", "/mm/v1/lock/acquire", None, |auth| {
            let message = LockAcquire {
                namespace: namespace.clone(),
                dir_path: dir_path.clone(),
                client_id,
                session_id: *auth.keys.session_id(),
                lock_id: reclaim.map(|id| *id.as_bytes()),
            };
            Ok(Some((Kind::LockAcquire, encode(&message)?)))
        });
        let response = match response {
            Ok(response) => response,
            Err(failure) => return Err(map_failure(failure)),
        };
        if response.status != 200 {
            return Err(map_failure(response.into_failure()));
        }
        let granted: LockGranted = response.decode().map_err(map_failure)?;
        let lock_id = LockId::from_bytes(granted.lock_id);
        if reclaim != Some(lock_id) {
            self.cache().active_batches.remove(&granted.dir_ino);
        }
        self.remember_lock(dir_path.as_str(), lock_id);
        Ok(LockResponse::Granted(GrantedLock {
            lock_id,
            dir_ino: granted.dir_ino,
            base: mm_base(granted.epoch, granted.base_seq, granted.dir_version),
            expires_at_ms: granted.expires_at_ms,
        }))
    }

    fn lock_renew(
        &self,
        lock_id: LockId,
        progress_bytes: u64,
    ) -> Result<LockResponse, RemoteError> {
        let message = LockRenew {
            lock_id: *lock_id.as_bytes(),
            progress_bytes: Some(progress_bytes),
        };
        let meta = encode(&message).map_err(map_failure)?;
        let response = self
            .call(
                "POST",
                "/mm/v1/lock/renew",
                Some((Kind::LockRenew, &meta)),
                None,
            )
            .map_err(map_failure)?;
        if response.status != 200 {
            return Err(map_failure(response.into_failure()));
        }
        let renewed: crate::mmap::proto::LockRenewed = response.decode().map_err(map_failure)?;
        Ok(LockResponse::Renewed {
            expires_at_ms: renewed.expires_at_ms,
        })
    }

    fn lock_release(&self, lock_id: LockId) -> Result<LockResponse, RemoteError> {
        let message = LockRelease {
            lock_id: *lock_id.as_bytes(),
        };
        let meta = encode(&message).map_err(map_failure)?;
        let response = self
            .call(
                "POST",
                "/mm/v1/lock/release",
                Some((Kind::LockRelease, &meta)),
                None,
            )
            .map_err(map_failure)?;
        match response.status {
            200 | 204 => {
                self.forget_lock(lock_id);
                Ok(LockResponse::Released)
            }
            423 => {
                // Release is best effort after a failed upload; a lost lease
                // is already released as far as this mount is concerned.
                self.forget_lock(lock_id);
                Ok(LockResponse::Released)
            }
            _ => Err(map_failure(response.into_failure())),
        }
    }

    // -----------------------------------------------------------------
    // status
    // -----------------------------------------------------------------

    /// `GET batch/{id}`.
    pub fn batch_status(&self, batch_id: BatchId) -> Result<BatchStatus, RemoteError> {
        self.batch_status_wire(batch_id).map_err(map_failure)
    }

    fn batch_status_wire(&self, batch_id: BatchId) -> Result<BatchStatus, WireFailure> {
        let suffix = format!("/mm/v1/batch/{}", batch_id.to_hex());
        let response = self.call("GET", &suffix, None, None)?;
        if response.status != 200 {
            return Err(response.into_failure());
        }
        let message: BatchStateMessage = response.decode()?;
        Ok(BatchStatus {
            batch_id: BatchId::from_bytes(message.batch_id),
            state: message.state,
            snapshot_seq: message.snapshot_seq.map(MmSeq::new),
            base_seq_after: message.base_seq_after.map(DirSeq::new),
            dir_version_after: message.dir_version_after,
            manifest_hash: message.manifest_hash,
            dir_path: message.dir_path,
        })
    }

    /// `GET version?dir_ino=...`.
    pub fn dir_version(&self, dir_ino: Ino) -> Result<DirVersionInfo, RemoteError> {
        let suffix = format!("/mm/v1/version?dir_ino={}", hex::encode(dir_ino));
        let response = self.call("GET", &suffix, None, None).map_err(map_failure)?;
        if response.status != 200 {
            return Err(map_failure(response.into_failure()));
        }
        let message: DirVersion = response.decode().map_err(map_failure)?;
        Ok(DirVersionInfo {
            epoch: message.epoch,
            snapshot_seq: MmSeq::new(message.snapshot_seq),
            base: mm_base(message.epoch, message.base_seq, message.dir_version),
            dir_path: message.dir_path,
        })
    }
}

fn failure_text(failure: &WireFailure) -> String {
    match failure {
        WireFailure::Transport(message) | WireFailure::Protocol(message) => message.clone(),
        WireFailure::Status { status, body } => {
            format!("HTTP {status} {}", body.code.as_str())
        }
    }
}

fn entry_from_wire(entry: WireEntry) -> Result<CheckoutEntry, RemoteError> {
    let ino = entry
        .ino
        .ok_or_else(|| RemoteError::Internal(format!("entry {} has no inode", entry.name)))?;
    let kind = match entry.kind {
        crate::mmap::proto::EntryKind::File => EntryKind::File,
        crate::mmap::proto::EntryKind::Symlink => EntryKind::Symlink,
        crate::mmap::proto::EntryKind::Dir => EntryKind::Dir,
    };
    let file_root = entry
        .file_root
        .ok_or_else(|| RemoteError::Internal(format!("entry {} has no file root", entry.name)))?;
    Ok(CheckoutEntry {
        name: entry.name,
        ino,
        kind,
        attrs: DirAttrs {
            mode: entry.mode,
            uid: entry.uid,
            gid: entry.gid,
            mtime_ns: i64::try_from(entry.mtime_ns)
                .map_err(|_| RemoteError::Internal("entry mtime overflows i64".to_owned()))?,
        },
        size: entry.size,
        file_root,
        content_hash: entry.content_hash,
        target: entry.target,
    })
}

fn verify_content(entry: &CheckoutEntry, bytes: &[u8]) -> Result<(), RemoteError> {
    let chunks = chunk_refs(bytes);
    let root = base::file_root(EntryKind::File, None, &chunks);
    if root != entry.file_root {
        return Err(RemoteError::Internal(format!(
            "checkout body for {} does not match its file root",
            entry.name
        )));
    }
    if let Some(hash) = entry.content_hash {
        if *blake3::hash(bytes).as_bytes() != hash {
            return Err(RemoteError::Internal(format!(
                "checkout body for {} does not match its content hash",
                entry.name
            )));
        }
    }
    Ok(())
}

fn chunk_refs(bytes: &[u8]) -> Vec<crate::store::sqlite::ChunkRef> {
    bytes
        .chunks(64 * 1024)
        .enumerate()
        .map(|(index, chunk)| crate::store::sqlite::ChunkRef {
            chunk_no: u32::try_from(index).unwrap_or(u32::MAX),
            hash: *blake3::hash(chunk).as_bytes(),
            offset: (index as u64) * 64 * 1024,
            len: u32::try_from(chunk.len()).unwrap_or(u32::MAX),
        })
        .collect()
}

fn signature_plan_from_wire(file: FileSignature) -> Result<SignatureFilePlan, RemoteError> {
    let signature = match file.state {
        SignatureState::Unchanged => None,
        SignatureState::Full => None,
        SignatureState::Delta => {
            let blocks = file
                .blocks
                .iter()
                .map(|block| {
                    BlockSignature::new(block.weak, block.strong, block.block_len)
                        .map_err(|error| RemoteError::Internal(error.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Some(
                Signature::new(file.block_size, file.size, blocks)
                    .map_err(|error| RemoteError::Internal(error.to_string()))?,
            )
        }
    };
    Ok(SignatureFilePlan {
        ino: file.ino,
        unchanged: file.state == SignatureState::Unchanged,
        signature,
    })
}

fn remote_result(result: UploadResult) -> RemoteResult {
    RemoteResult {
        batch_id: BatchId::from_bytes(result.batch_id),
        base: mm_base(
            result.epoch,
            result.base_seq_after,
            result.dir_version_after,
        ),
        snapshot_seq: MmSeq::new(result.snapshot_seq),
        dir_version: result.dir_version_after,
        entry_count: result.entry_count,
        bytes: result.bytes,
    }
}

fn status_result(
    request: &RemoteCommit,
    status: &BatchStatus,
) -> Result<RemoteResult, RemoteError> {
    let snapshot_seq = status
        .snapshot_seq
        .ok_or_else(|| RemoteError::Internal("committed batch lacks a sequence".to_owned()))?;
    let dir_seq = status.base_seq_after.ok_or_else(|| {
        RemoteError::Internal("committed batch lacks a directory sequence".to_owned())
    })?;
    let dir_version = status.dir_version_after.ok_or_else(|| {
        RemoteError::Internal("committed batch lacks a directory version".to_owned())
    })?;
    Ok(RemoteResult {
        batch_id: request.batch_id,
        base: mm_base(request.base.epoch, dir_seq.get(), dir_version),
        snapshot_seq,
        dir_version,
        entry_count: u32::try_from(request.manifest.len()).unwrap_or(u32::MAX),
        bytes: request.bytes,
    })
}
