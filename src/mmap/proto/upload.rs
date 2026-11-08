//! Request and response messages, part two: upload, lock, batch and version.
//!
//! The same strictness as [`super::messages`] applies. In particular
//! `UPLOAD_BEGIN` enforces the manifest's structural completeness: every
//! directory entry in `entries` must have exactly one matching record in
//! `structural`, and the two lists must agree on the operation.

use std::collections::{BTreeMap, BTreeSet};

use super::error::{ErrorCode, ProtoError};
use super::field::{FieldWriter, Fields};
use super::kind::Kind;
use super::limits::Limits;
use super::messages::Message;
use super::tag;
use super::types::{
    BatchState, DirAttrs, Entry, EntryKind, EntryOp, MAX_DETAIL, MAX_NAME, MAX_PATH, PlanItem,
    UploadMode, check_name, check_namespace, check_path,
};

/// `UPLOAD_BEGIN`: open a batch with the complete manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadBegin {
    /// Namespace label.
    pub namespace: String,
    /// Canonical directory path.
    pub dir_path: String,
    /// Directory inode.
    pub dir_ino: [u8; 16],
    /// Database epoch.
    pub epoch: u64,
    /// Per-directory `dir_seq`.
    pub base_seq: u64,
    /// Directory version the client based the batch on.
    pub dir_version: [u8; 32],
    /// Client-generated batch id.
    pub batch_id: [u8; 16],
    /// Lock id.
    pub lock_id: [u8; 16],
    /// Authenticated client id.
    pub client_id: [u8; 16],
    /// Canonical manifest hash.
    pub manifest_hash: [u8; 32],
    /// All direct entries.
    pub entries: Vec<Entry>,
    /// Direct child directories, one per entry.
    pub structural: Vec<Entry>,
    /// Directory attributes.
    pub dir_attrs: DirAttrs,
    /// Delta or full.
    pub mode: UploadMode,
}

impl UploadBegin {
    /// Check the manifest and structural completeness.
    ///
    /// # Errors
    ///
    /// Any entry, duplicate, completeness or path error.
    pub fn validate(&self) -> Result<(), ProtoError> {
        check_namespace(&self.namespace)?;
        check_path(&self.dir_path)?;
        let limits = Limits::new();
        if self.entries.len() > limits.max_entries as usize {
            return Err(ProtoError::TooManyRecords {
                tag: tag::ENTRIES,
                count: self.entries.len() as u32,
                cap: limits.max_entries,
            });
        }
        if self.structural.len() > limits.max_entries as usize {
            return Err(ProtoError::TooManyRecords {
                tag: tag::STRUCTURAL,
                count: self.structural.len() as u32,
                cap: limits.max_entries,
            });
        }

        let mut names = BTreeSet::new();
        let mut dirs: BTreeMap<&str, EntryOp> = BTreeMap::new();
        for entry in &self.entries {
            entry.validate_manifest()?;
            if !names.insert(entry.name.as_str()) {
                return Err(ProtoError::Inconsistent("duplicate manifest name"));
            }
            if entry.kind == EntryKind::Dir {
                dirs.insert(entry.name.as_str(), entry.op);
            }
        }

        let mut structural_names = BTreeSet::new();
        for entry in &self.structural {
            if entry.kind != EntryKind::Dir {
                return Err(ProtoError::Inconsistent(
                    "structural entry is not a directory",
                ));
            }
            if !matches!(
                entry.op,
                EntryOp::Keep | EntryOp::DirAdd | EntryOp::DirRemove | EntryOp::DirRename
            ) {
                return Err(ProtoError::Inconsistent("structural entry has a file op"));
            }
            entry.validate_basic()?;
            if !structural_names.insert(entry.name.as_str()) {
                return Err(ProtoError::Inconsistent("duplicate structural name"));
            }
            match dirs.get(entry.name.as_str()) {
                Some(op) if *op == entry.op => {}
                Some(_) => {
                    return Err(ProtoError::Inconsistent(
                        "structural op differs from manifest entry",
                    ));
                }
                None => {
                    return Err(ProtoError::Inconsistent(
                        "structural entry is absent from the manifest",
                    ));
                }
            }
        }
        for name in dirs.keys() {
            if !structural_names.contains(name) {
                return Err(ProtoError::Inconsistent(
                    "manifest directory is absent from structural",
                ));
            }
        }
        Ok(())
    }
}

impl Message for UploadBegin {
    const KIND: Kind = Kind::UploadBegin;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        self.validate()?;
        let limits = Limits::new();
        let mut writer = FieldWriter::new();
        writer.string(tag::NAMESPACE, &self.namespace)?;
        writer.string(tag::DIR_PATH, &self.dir_path)?;
        writer.array(tag::DIR_INO, &self.dir_ino)?;
        writer.u64(tag::EPOCH, self.epoch)?;
        writer.u64(tag::BASE_SEQ, self.base_seq)?;
        writer.array(tag::DIR_VERSION, &self.dir_version)?;
        writer.array(tag::BATCH_ID, &self.batch_id)?;
        writer.array(tag::LOCK_ID, &self.lock_id)?;
        writer.array(tag::CLIENT_ID, &self.client_id)?;
        writer.array(tag::MANIFEST_HASH, &self.manifest_hash)?;
        super::types::encode_entry_list(
            &mut writer,
            tag::ENTRIES,
            limits.max_entries,
            &self.entries,
        )?;
        super::types::encode_entry_list(
            &mut writer,
            tag::STRUCTURAL,
            limits.max_entries,
            &self.structural,
        )?;
        self.dir_attrs.encode_into(&mut writer, tag::DIR_ATTRS)?;
        writer.u32(tag::MODE, self.mode.as_u32())?;
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let limits = Limits::new();
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let namespace = fields
            .string(tag::NAMESPACE, super::types::MAX_NAMESPACE)?
            .to_owned();
        let dir_path = fields.string(tag::DIR_PATH, MAX_PATH)?.to_owned();
        let dir_ino = fields.array(tag::DIR_INO)?;
        let epoch = fields.u64(tag::EPOCH)?;
        let base_seq = fields.u64(tag::BASE_SEQ)?;
        let dir_version = fields.array(tag::DIR_VERSION)?;
        let batch_id = fields.array(tag::BATCH_ID)?;
        let lock_id = fields.array(tag::LOCK_ID)?;
        let client_id = fields.array(tag::CLIENT_ID)?;
        let manifest_hash = fields.array(tag::MANIFEST_HASH)?;
        let entry_records = fields.list(tag::ENTRIES, limits.max_entries)?;
        let structural_records = fields.list(tag::STRUCTURAL, limits.max_entries)?;
        let dir_attrs = DirAttrs::decode_from(fields.nested(tag::DIR_ATTRS)?)?;
        let mode = UploadMode::from_u32(fields.u32(tag::MODE)?)?;
        fields.finish()?;
        let entries = super::types::decode_entry_list(&entry_records, limits.max_entries)?;
        let structural = super::types::decode_entry_list(&structural_records, limits.max_entries)?;
        let begin = Self {
            namespace,
            dir_path,
            dir_ino,
            epoch,
            base_seq,
            dir_version,
            batch_id,
            lock_id,
            client_id,
            manifest_hash,
            entries,
            structural,
            dir_attrs,
            mode,
        };
        begin.validate()?;
        Ok(begin)
    }
}

/// `UPLOAD_PLAN`: what the server will apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadPlan {
    /// Batch id.
    pub batch_id: [u8; 16],
    /// Database epoch.
    pub epoch: u64,
    /// Base `dir_seq`.
    pub base_seq: u64,
    /// Directory version.
    pub dir_version: [u8; 32],
    /// Per-entry plan.
    pub plan: Vec<PlanItem>,
    /// Extended lock deadline.
    pub lock_expires_at_ms: u64,
    /// Server caps.
    pub limits: Limits,
}

impl UploadPlan {
    /// Check the plan invariants.
    ///
    /// # Errors
    ///
    /// Duplicate names, too many items or invalid limits.
    pub fn validate(&self) -> Result<(), ProtoError> {
        let max = Limits::new().max_entries;
        if self.plan.len() > max as usize {
            return Err(ProtoError::TooManyRecords {
                tag: tag::PLAN,
                count: self.plan.len() as u32,
                cap: max,
            });
        }
        let mut names = BTreeSet::new();
        for item in &self.plan {
            if !names.insert(item.name.as_str()) {
                return Err(ProtoError::Inconsistent("duplicate plan name"));
            }
        }
        self.limits.validate()?;
        Ok(())
    }
}

impl Message for UploadPlan {
    const KIND: Kind = Kind::UploadPlan;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        self.validate()?;
        let records = self
            .plan
            .iter()
            .map(PlanItem::encode_record)
            .collect::<Result<Vec<_>, _>>()?;
        let mut writer = FieldWriter::new();
        writer.array(tag::BATCH_ID, &self.batch_id)?;
        writer.u64(tag::EPOCH, self.epoch)?;
        writer.u64(tag::BASE_SEQ, self.base_seq)?;
        writer.array(tag::DIR_VERSION, &self.dir_version)?;
        writer.list(tag::PLAN, Limits::new().max_entries, &records)?;
        writer.u64(tag::EXPIRES_AT_MS, self.lock_expires_at_ms)?;
        self.limits.encode_into(&mut writer, tag::LIMITS)?;
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let limits = Limits::new();
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let batch_id = fields.array(tag::BATCH_ID)?;
        let epoch = fields.u64(tag::EPOCH)?;
        let base_seq = fields.u64(tag::BASE_SEQ)?;
        let dir_version = fields.array(tag::DIR_VERSION)?;
        let records = fields.list(tag::PLAN, limits.max_entries)?;
        let lock_expires_at_ms = fields.u64(tag::EXPIRES_AT_MS)?;
        let advertised = Limits::decode_from(fields.nested(tag::LIMITS)?)?;
        fields.finish()?;
        let plan = records
            .iter()
            .map(|record| PlanItem::decode_record(record))
            .collect::<Result<Vec<_>, _>>()?;
        let message = Self {
            batch_id,
            epoch,
            base_seq,
            dir_version,
            plan,
            lock_expires_at_ms,
            limits: advertised,
        };
        message.validate()?;
        Ok(message)
    }
}

/// `UPLOAD_COMMIT`: apply the batch; the payload is the instruction stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadCommit {
    /// Namespace label.
    pub namespace: String,
    /// Batch id.
    pub batch_id: [u8; 16],
    /// Lock id.
    pub lock_id: [u8; 16],
    /// Database epoch.
    pub epoch: u64,
    /// Per-directory `dir_seq`.
    pub base_seq: u64,
    /// Directory version.
    pub dir_version: [u8; 32],
    /// Manifest hash repeated for idempotency.
    pub manifest_hash: [u8; 32],
}

impl UploadCommit {
    /// Check the request invariants.
    ///
    /// # Errors
    ///
    /// A namespace error.
    pub fn validate(&self) -> Result<(), ProtoError> {
        check_namespace(&self.namespace)
    }
}

impl Message for UploadCommit {
    const KIND: Kind = Kind::UploadCommit;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        self.validate()?;
        let mut writer = FieldWriter::new();
        writer.string(tag::NAMESPACE, &self.namespace)?;
        writer.array(tag::BATCH_ID, &self.batch_id)?;
        writer.array(tag::LOCK_ID, &self.lock_id)?;
        writer.u64(tag::EPOCH, self.epoch)?;
        writer.u64(tag::BASE_SEQ, self.base_seq)?;
        writer.array(tag::DIR_VERSION, &self.dir_version)?;
        writer.array(tag::MANIFEST_HASH, &self.manifest_hash)?;
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let commit = Self {
            namespace: fields
                .string(tag::NAMESPACE, super::types::MAX_NAMESPACE)?
                .to_owned(),
            batch_id: fields.array(tag::BATCH_ID)?,
            lock_id: fields.array(tag::LOCK_ID)?,
            epoch: fields.u64(tag::EPOCH)?,
            base_seq: fields.u64(tag::BASE_SEQ)?,
            dir_version: fields.array(tag::DIR_VERSION)?,
            manifest_hash: fields.array(tag::MANIFEST_HASH)?,
        };
        fields.finish()?;
        commit.validate()?;
        Ok(commit)
    }
}

/// `UPLOAD_RESULT`: the committed batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadResult {
    /// New global `mm_seq`.
    pub snapshot_seq: u64,
    /// Database epoch.
    pub epoch: u64,
    /// New `dir_seq`.
    pub base_seq_after: u64,
    /// New directory version.
    pub dir_version_after: [u8; 32],
    /// Batch id.
    pub batch_id: [u8; 16],
    /// Number of direct entries.
    pub entry_count: u32,
    /// Bytes committed.
    pub bytes: u64,
    /// Commit time.
    pub committed_at_ms: u64,
}

impl Message for UploadResult {
    const KIND: Kind = Kind::UploadResult;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        let max = Limits::new().max_entries;
        if self.entry_count > max {
            return Err(ProtoError::TooManyRecords {
                tag: tag::ENTRY_COUNT,
                count: self.entry_count,
                cap: max,
            });
        }
        if self.bytes > Limits::new().max_batch_bytes {
            return Err(ProtoError::ValueOutOfRange {
                tag: tag::BYTES,
                value: self.bytes,
                max: Limits::new().max_batch_bytes,
            });
        }
        let mut writer = FieldWriter::new();
        writer.u64(tag::SNAPSHOT_SEQ, self.snapshot_seq)?;
        writer.u64(tag::EPOCH, self.epoch)?;
        writer.u64(tag::BASE_SEQ_AFTER, self.base_seq_after)?;
        writer.array(tag::DIR_VERSION_AFTER, &self.dir_version_after)?;
        writer.array(tag::BATCH_ID, &self.batch_id)?;
        writer.u32(tag::ENTRY_COUNT, self.entry_count)?;
        writer.u64(tag::BYTES, self.bytes)?;
        writer.u64(tag::COMMITTED_AT_MS, self.committed_at_ms)?;
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let result = Self {
            snapshot_seq: fields.u64(tag::SNAPSHOT_SEQ)?,
            epoch: fields.u64(tag::EPOCH)?,
            base_seq_after: fields.u64(tag::BASE_SEQ_AFTER)?,
            dir_version_after: fields.array(tag::DIR_VERSION_AFTER)?,
            batch_id: fields.array(tag::BATCH_ID)?,
            entry_count: fields.u32(tag::ENTRY_COUNT)?,
            bytes: fields.u64(tag::BYTES)?,
            committed_at_ms: fields.u64(tag::COMMITTED_AT_MS)?,
        };
        fields.finish()?;
        let max = Limits::new().max_entries;
        if result.entry_count > max {
            return Err(ProtoError::TooManyRecords {
                tag: tag::ENTRY_COUNT,
                count: result.entry_count,
                cap: max,
            });
        }
        Ok(result)
    }
}

/// `UPLOAD_ABORT`: discard a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadAbort {
    /// Batch id.
    pub batch_id: [u8; 16],
    /// Lock id.
    pub lock_id: [u8; 16],
}

impl Message for UploadAbort {
    const KIND: Kind = Kind::UploadAbort;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        let mut writer = FieldWriter::new();
        writer.array(tag::BATCH_ID, &self.batch_id)?;
        writer.array(tag::LOCK_ID, &self.lock_id)?;
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let abort = Self {
            batch_id: fields.array(tag::BATCH_ID)?,
            lock_id: fields.array(tag::LOCK_ID)?,
        };
        fields.finish()?;
        Ok(abort)
    }
}

/// `ABORTED`: abort acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Aborted {
    /// Batch id.
    pub batch_id: [u8; 16],
    /// Optional reason.
    pub reason: Option<String>,
}

impl Message for Aborted {
    const KIND: Kind = Kind::Aborted;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        let mut writer = FieldWriter::new();
        writer.array(tag::BATCH_ID, &self.batch_id)?;
        if let Some(reason) = &self.reason {
            writer.string(tag::REASON, reason)?;
        }
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let aborted = Self {
            batch_id: fields.array(tag::BATCH_ID)?,
            reason: fields
                .opt_string(tag::REASON, MAX_DETAIL)?
                .map(str::to_owned),
        };
        fields.finish()?;
        Ok(aborted)
    }
}

/// `LOCK_ACQUIRE`: take the directory upload lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockAcquire {
    /// Namespace label.
    pub namespace: String,
    /// Canonical directory path.
    pub dir_path: String,
    /// Authenticated client id.
    pub client_id: [u8; 16],
    /// Session id.
    pub session_id: [u8; 16],
    /// Reclaim this lock id when it still belongs to the same client.
    pub lock_id: Option<[u8; 16]>,
}

impl LockAcquire {
    /// Check the request invariants.
    ///
    /// # Errors
    ///
    /// A namespace or path error.
    pub fn validate(&self) -> Result<(), ProtoError> {
        check_namespace(&self.namespace)?;
        check_path(&self.dir_path)
    }
}

impl Message for LockAcquire {
    const KIND: Kind = Kind::LockAcquire;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        self.validate()?;
        let mut writer = FieldWriter::new();
        writer.string(tag::NAMESPACE, &self.namespace)?;
        writer.string(tag::DIR_PATH, &self.dir_path)?;
        writer.array(tag::CLIENT_ID, &self.client_id)?;
        writer.array(tag::SESSION_ID, &self.session_id)?;
        if let Some(lock_id) = self.lock_id {
            writer.array(tag::LOCK_ID, &lock_id)?;
        }
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let acquire = Self {
            namespace: fields
                .string(tag::NAMESPACE, super::types::MAX_NAMESPACE)?
                .to_owned(),
            dir_path: fields.string(tag::DIR_PATH, MAX_PATH)?.to_owned(),
            client_id: fields.array(tag::CLIENT_ID)?,
            session_id: fields.array(tag::SESSION_ID)?,
            lock_id: fields.opt_array::<16>(tag::LOCK_ID)?,
        };
        fields.finish()?;
        acquire.validate()?;
        Ok(acquire)
    }
}

/// `LOCK_GRANTED`: the lock and the base it protects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockGranted {
    /// Lock id.
    pub lock_id: [u8; 16],
    /// Canonical directory path.
    pub dir_path: String,
    /// Directory inode.
    pub dir_ino: [u8; 16],
    /// Database epoch.
    pub epoch: u64,
    /// Per-directory `dir_seq`.
    pub base_seq: u64,
    /// Global `mm_seq`.
    pub snapshot_seq: u64,
    /// Directory version.
    pub dir_version: [u8; 32],
    /// Lease deadline.
    pub expires_at_ms: u64,
    /// Lease duration.
    pub ttl_ms: u32,
}

impl LockGranted {
    /// Check the response invariants.
    ///
    /// # Errors
    ///
    /// A path error or a zero TTL.
    pub fn validate(&self) -> Result<(), ProtoError> {
        check_path(&self.dir_path)?;
        if self.ttl_ms == 0 {
            return Err(ProtoError::Inconsistent("zero lock TTL"));
        }
        Ok(())
    }

    /// The P1A-facing base view.
    pub fn mm_base(&self) -> super::types::MmBaseWire {
        super::types::MmBaseWire {
            epoch: self.epoch,
            base_seq: self.base_seq,
            snapshot_seq: self.snapshot_seq,
            dir_ino: self.dir_ino,
            dir_version: self.dir_version,
        }
    }
}

impl Message for LockGranted {
    const KIND: Kind = Kind::LockGranted;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        self.validate()?;
        let mut writer = FieldWriter::new();
        writer.array(tag::LOCK_ID, &self.lock_id)?;
        writer.string(tag::DIR_PATH, &self.dir_path)?;
        writer.array(tag::DIR_INO, &self.dir_ino)?;
        writer.u64(tag::EPOCH, self.epoch)?;
        writer.u64(tag::BASE_SEQ, self.base_seq)?;
        writer.u64(tag::SNAPSHOT_SEQ, self.snapshot_seq)?;
        writer.array(tag::DIR_VERSION, &self.dir_version)?;
        writer.u64(tag::EXPIRES_AT_MS, self.expires_at_ms)?;
        writer.u32(tag::TTL_MS, self.ttl_ms)?;
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let granted = Self {
            lock_id: fields.array(tag::LOCK_ID)?,
            dir_path: fields.string(tag::DIR_PATH, MAX_PATH)?.to_owned(),
            dir_ino: fields.array(tag::DIR_INO)?,
            epoch: fields.u64(tag::EPOCH)?,
            base_seq: fields.u64(tag::BASE_SEQ)?,
            snapshot_seq: fields.u64(tag::SNAPSHOT_SEQ)?,
            dir_version: fields.array(tag::DIR_VERSION)?,
            expires_at_ms: fields.u64(tag::EXPIRES_AT_MS)?,
            ttl_ms: fields.u32(tag::TTL_MS)?,
        };
        fields.finish()?;
        granted.validate()?;
        Ok(granted)
    }
}

/// `LOCK_RENEW`: extend the lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockRenew {
    /// Lock id.
    pub lock_id: [u8; 16],
    /// Bytes acknowledged since the last renew.
    pub progress_bytes: Option<u64>,
}

impl Message for LockRenew {
    const KIND: Kind = Kind::LockRenew;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        let mut writer = FieldWriter::new();
        writer.array(tag::LOCK_ID, &self.lock_id)?;
        if let Some(progress) = self.progress_bytes {
            writer.u64(tag::PROGRESS_BYTES, progress)?;
        }
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let renew = Self {
            lock_id: fields.array(tag::LOCK_ID)?,
            progress_bytes: fields.opt_u64(tag::PROGRESS_BYTES)?,
        };
        fields.finish()?;
        Ok(renew)
    }
}

/// `LOCK_RENEWED`: the new deadline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockRenewed {
    /// Lock id.
    pub lock_id: [u8; 16],
    /// New deadline.
    pub expires_at_ms: u64,
}

impl Message for LockRenewed {
    const KIND: Kind = Kind::LockRenewed;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        let mut writer = FieldWriter::new();
        writer.array(tag::LOCK_ID, &self.lock_id)?;
        writer.u64(tag::EXPIRES_AT_MS, self.expires_at_ms)?;
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let renewed = Self {
            lock_id: fields.array(tag::LOCK_ID)?,
            expires_at_ms: fields.u64(tag::EXPIRES_AT_MS)?,
        };
        fields.finish()?;
        Ok(renewed)
    }
}

/// `LOCK_RELEASE`: drop the lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockRelease {
    /// Lock id.
    pub lock_id: [u8; 16],
}

impl Message for LockRelease {
    const KIND: Kind = Kind::LockRelease;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        let mut writer = FieldWriter::new();
        writer.array(tag::LOCK_ID, &self.lock_id)?;
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let release = Self {
            lock_id: fields.array(tag::LOCK_ID)?,
        };
        fields.finish()?;
        Ok(release)
    }
}

/// `LOCK_RELEASED`: release acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockReleased {
    /// Lock id.
    pub lock_id: [u8; 16],
}

impl Message for LockReleased {
    const KIND: Kind = Kind::LockReleased;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        let mut writer = FieldWriter::new();
        writer.array(tag::LOCK_ID, &self.lock_id)?;
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let released = Self {
            lock_id: fields.array(tag::LOCK_ID)?,
        };
        fields.finish()?;
        Ok(released)
    }
}

/// `BATCH_STATUS`: ask for a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchStatus {
    /// Batch id.
    pub batch_id: [u8; 16],
}

impl Message for BatchStatus {
    const KIND: Kind = Kind::BatchStatus;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        let mut writer = FieldWriter::new();
        writer.array(tag::BATCH_ID, &self.batch_id)?;
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let status = Self {
            batch_id: fields.array(tag::BATCH_ID)?,
        };
        fields.finish()?;
        Ok(status)
    }
}

/// `BATCH_STATE`: the current batch state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchStateMessage {
    /// Batch id.
    pub batch_id: [u8; 16],
    /// State.
    pub state: BatchState,
    /// New global sequence, when committed.
    pub snapshot_seq: Option<u64>,
    /// New `dir_seq`, when committed.
    pub base_seq_after: Option<u64>,
    /// New directory version, when committed.
    pub dir_version_after: Option<[u8; 32]>,
    /// Manifest hash.
    pub manifest_hash: [u8; 32],
    /// Directory path.
    pub dir_path: String,
}

impl BatchStateMessage {
    /// Check the state/field consistency.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Inconsistent`] when a committed batch lacks its result,
    /// or an open/aborted batch carries one.
    pub fn validate(&self) -> Result<(), ProtoError> {
        check_path(&self.dir_path)?;
        let after = (
            self.snapshot_seq,
            self.base_seq_after,
            self.dir_version_after,
        );
        match self.state {
            BatchState::Committed => {
                if after.0.is_none() || after.1.is_none() || after.2.is_none() {
                    return Err(ProtoError::Inconsistent("committed batch lacks its result"));
                }
            }
            BatchState::Open | BatchState::Aborted => {
                if after.0.is_some() || after.1.is_some() || after.2.is_some() {
                    return Err(ProtoError::Inconsistent(
                        "uncommitted batch carries a result",
                    ));
                }
            }
        }
        Ok(())
    }
}

impl Message for BatchStateMessage {
    const KIND: Kind = Kind::BatchState;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        self.validate()?;
        let mut writer = FieldWriter::new();
        writer.array(tag::BATCH_ID, &self.batch_id)?;
        writer.u8(tag::BATCH_STATE, self.state.as_u8())?;
        if let Some(seq) = self.snapshot_seq {
            writer.u64(tag::SNAPSHOT_SEQ, seq)?;
        }
        if let Some(seq) = self.base_seq_after {
            writer.u64(tag::BASE_SEQ_AFTER, seq)?;
        }
        if let Some(version) = self.dir_version_after {
            writer.array(tag::DIR_VERSION_AFTER, &version)?;
        }
        writer.array(tag::MANIFEST_HASH, &self.manifest_hash)?;
        writer.string(tag::DIR_PATH, &self.dir_path)?;
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let message = Self {
            batch_id: fields.array(tag::BATCH_ID)?,
            state: BatchState::from_u8(fields.u8(tag::BATCH_STATE)?)?,
            snapshot_seq: fields.opt_u64(tag::SNAPSHOT_SEQ)?,
            base_seq_after: fields.opt_u64(tag::BASE_SEQ_AFTER)?,
            dir_version_after: fields.opt_array::<32>(tag::DIR_VERSION_AFTER)?,
            manifest_hash: fields.array(tag::MANIFEST_HASH)?,
            dir_path: fields.string(tag::DIR_PATH, MAX_PATH)?.to_owned(),
        };
        fields.finish()?;
        message.validate()?;
        Ok(message)
    }
}

/// `DIR_VERSION_REQ`: ask for one directory version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirVersionRequest {
    /// Namespace label.
    pub namespace: String,
    /// Directory inode.
    pub dir_ino: [u8; 16],
    /// Optional path for diagnostics.
    pub dir_path: Option<String>,
}

impl DirVersionRequest {
    /// Check the request invariants.
    ///
    /// # Errors
    ///
    /// A namespace or path error.
    pub fn validate(&self) -> Result<(), ProtoError> {
        check_namespace(&self.namespace)?;
        if let Some(path) = &self.dir_path {
            check_path(path)?;
        }
        Ok(())
    }
}

impl Message for DirVersionRequest {
    const KIND: Kind = Kind::DirVersionReq;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        self.validate()?;
        let mut writer = FieldWriter::new();
        writer.string(tag::NAMESPACE, &self.namespace)?;
        writer.array(tag::DIR_INO, &self.dir_ino)?;
        if let Some(path) = &self.dir_path {
            writer.string(tag::DIR_PATH, path)?;
        }
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let request = Self {
            namespace: fields
                .string(tag::NAMESPACE, super::types::MAX_NAMESPACE)?
                .to_owned(),
            dir_ino: fields.array(tag::DIR_INO)?,
            dir_path: fields
                .opt_string(tag::DIR_PATH, MAX_PATH)?
                .map(str::to_owned),
        };
        fields.finish()?;
        request.validate()?;
        Ok(request)
    }
}

/// `DIR_VERSION`: the current directory version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirVersion {
    /// Database epoch.
    pub epoch: u64,
    /// Global `mm_seq`.
    pub snapshot_seq: u64,
    /// Per-directory `dir_seq`.
    pub base_seq: u64,
    /// Directory version.
    pub dir_version: [u8; 32],
    /// Directory inode.
    pub dir_ino: [u8; 16],
    /// Canonical directory path.
    pub dir_path: String,
}

impl DirVersion {
    /// Check the response invariants.
    ///
    /// # Errors
    ///
    /// A path error.
    pub fn validate(&self) -> Result<(), ProtoError> {
        check_path(&self.dir_path)
    }

    /// The P1A-facing base view.
    pub fn mm_base(&self) -> super::types::MmBaseWire {
        super::types::MmBaseWire {
            epoch: self.epoch,
            base_seq: self.base_seq,
            snapshot_seq: self.snapshot_seq,
            dir_ino: self.dir_ino,
            dir_version: self.dir_version,
        }
    }
}

impl Message for DirVersion {
    const KIND: Kind = Kind::DirVersion;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        self.validate()?;
        let mut writer = FieldWriter::new();
        writer.u64(tag::EPOCH, self.epoch)?;
        writer.u64(tag::SNAPSHOT_SEQ, self.snapshot_seq)?;
        writer.u64(tag::BASE_SEQ, self.base_seq)?;
        writer.array(tag::DIR_VERSION, &self.dir_version)?;
        writer.array(tag::DIR_INO, &self.dir_ino)?;
        writer.string(tag::DIR_PATH, &self.dir_path)?;
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let version = Self {
            epoch: fields.u64(tag::EPOCH)?,
            snapshot_seq: fields.u64(tag::SNAPSHOT_SEQ)?,
            base_seq: fields.u64(tag::BASE_SEQ)?,
            dir_version: fields.array(tag::DIR_VERSION)?,
            dir_ino: fields.array(tag::DIR_INO)?,
            dir_path: fields.string(tag::DIR_PATH, MAX_PATH)?.to_owned(),
        };
        fields.finish()?;
        version.validate()?;
        Ok(version)
    }
}

/// `ERROR`: the terminal error body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorBody {
    /// Stable error code.
    pub code: ErrorCode,
    /// Human-readable detail.
    pub detail: Option<String>,
    /// Ask the client for a full retry.
    pub retry_full: bool,
    /// Missing entry names.
    pub missing: Vec<String>,
    /// Expected hash.
    pub expected: Option<[u8; 32]>,
    /// Actual hash.
    pub actual: Option<[u8; 32]>,
    /// Retry hint.
    pub retry_after_ms: Option<u64>,
    /// Lock owner.
    pub owner_client: Option<[u8; 16]>,
    /// Lock deadline.
    pub expires_at_ms: Option<u64>,
    /// Free-form reason.
    pub reason: Option<String>,
    /// Directory path.
    pub dir_path: Option<String>,
    /// Directory inode.
    pub dir_ino: Option<[u8; 16]>,
    /// Server epoch.
    pub epoch: Option<u64>,
    /// Server snapshot.
    pub snapshot_seq: Option<u64>,
    /// Server `dir_seq`.
    pub base_seq: Option<u64>,
    /// The sequence the client asked for.
    pub request_base_seq: Option<u64>,
    /// Server directory version.
    pub dir_version: Option<[u8; 32]>,
}

impl ErrorBody {
    /// A minimal error with only a code.
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            detail: None,
            retry_full: false,
            missing: Vec::new(),
            expected: None,
            actual: None,
            retry_after_ms: None,
            owner_client: None,
            expires_at_ms: None,
            reason: None,
            dir_path: None,
            dir_ino: None,
            epoch: None,
            snapshot_seq: None,
            base_seq: None,
            request_base_seq: None,
            dir_version: None,
        }
    }

    /// The HTTP status this body maps to.
    pub const fn http_status(&self) -> u16 {
        self.code.http_status()
    }

    /// Check the code-specific fields.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Inconsistent`] when a code-specific field is missing or
    /// a field that belongs to another code is present.
    pub fn validate(&self) -> Result<(), ProtoError> {
        if let Some(detail) = &self.detail {
            if detail.len() > MAX_DETAIL {
                return Err(ProtoError::ValueOutOfRange {
                    tag: tag::DETAIL,
                    value: detail.len() as u64,
                    max: MAX_DETAIL as u64,
                });
            }
        }
        if let Some(path) = &self.dir_path {
            check_path(path)?;
        }
        if self.retry_full && !self.code.requests_full_retry() {
            return Err(ProtoError::Inconsistent("retry_full on a non-hash error"));
        }
        if self.missing.len() > Limits::new().max_entries as usize {
            return Err(ProtoError::TooManyRecords {
                tag: tag::MISSING,
                count: self.missing.len() as u32,
                cap: Limits::new().max_entries,
            });
        }
        for name in &self.missing {
            check_name(name)?;
        }
        match self.code {
            ErrorCode::LockHeld => {
                if self.owner_client.is_none() || self.expires_at_ms.is_none() {
                    return Err(ProtoError::Inconsistent("LOCK_HELD lacks owner fields"));
                }
            }
            ErrorCode::LockLost | ErrorCode::LockExpired => {
                if self.reason.is_none() {
                    return Err(ProtoError::Inconsistent("lock loss lacks a reason"));
                }
            }
            ErrorCode::BaseChanged => {
                if self.epoch.is_none()
                    || self.snapshot_seq.is_none()
                    || self.base_seq.is_none()
                    || self.dir_version.is_none()
                    || self.dir_ino.is_none()
                {
                    return Err(ProtoError::Inconsistent("BASE_CHANGED lacks current base"));
                }
            }
            ErrorCode::ManifestIncomplete => {
                if self.missing.is_empty() {
                    return Err(ProtoError::Inconsistent(
                        "MANIFEST_INCOMPLETE lacks missing names",
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl Message for ErrorBody {
    const KIND: Kind = Kind::Error;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        self.validate()?;
        let mut writer = FieldWriter::new();
        writer.u16(tag::ERROR_CODE, self.code.as_u16())?;
        if let Some(detail) = &self.detail {
            writer.string(tag::DETAIL, detail)?;
        }
        if self.retry_full {
            writer.u8(tag::RETRY_FULL, 1)?;
        }
        if !self.missing.is_empty() {
            let records = self
                .missing
                .iter()
                .map(|name| {
                    let mut record = FieldWriter::new();
                    record.string(tag::NAME, name)?;
                    Ok(record.into_bytes())
                })
                .collect::<Result<Vec<_>, ProtoError>>()?;
            writer.list(tag::MISSING, Limits::new().max_entries, &records)?;
        }
        if let Some(hash) = self.expected {
            writer.array(tag::EXPECTED, &hash)?;
        }
        if let Some(hash) = self.actual {
            writer.array(tag::ACTUAL, &hash)?;
        }
        if let Some(ms) = self.retry_after_ms {
            writer.u64(tag::RETRY_AFTER_MS, ms)?;
        }
        if let Some(owner) = self.owner_client {
            writer.array(tag::OWNER_CLIENT, &owner)?;
        }
        if let Some(ms) = self.expires_at_ms {
            writer.u64(tag::EXPIRES_AT_MS, ms)?;
        }
        if let Some(reason) = &self.reason {
            writer.string(tag::REASON, reason)?;
        }
        if let Some(path) = &self.dir_path {
            writer.string(tag::DIR_PATH, path)?;
        }
        if let Some(ino) = self.dir_ino {
            writer.array(tag::DIR_INO, &ino)?;
        }
        if let Some(epoch) = self.epoch {
            writer.u64(tag::EPOCH, epoch)?;
        }
        if let Some(seq) = self.snapshot_seq {
            writer.u64(tag::SNAPSHOT_SEQ, seq)?;
        }
        if let Some(seq) = self.base_seq {
            writer.u64(tag::BASE_SEQ, seq)?;
        }
        if let Some(seq) = self.request_base_seq {
            writer.u64(tag::REQUEST_BASE_SEQ, seq)?;
        }
        if let Some(version) = self.dir_version {
            writer.array(tag::DIR_VERSION, &version)?;
        }
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let code = ErrorCode::from_u16(fields.u16(tag::ERROR_CODE)?)?;
        let detail = fields
            .opt_string(tag::DETAIL, MAX_DETAIL)?
            .map(str::to_owned);
        let retry_full = match fields.opt_u8(tag::RETRY_FULL)? {
            None | Some(0) => false,
            Some(1) => true,
            Some(other) => {
                return Err(ProtoError::BadEnum {
                    tag: tag::RETRY_FULL,
                    value: u64::from(other),
                });
            }
        };
        let missing = match fields.opt_list(tag::MISSING, Limits::new().max_entries)? {
            records if records.is_empty() => Vec::new(),
            records => records
                .iter()
                .map(|record| {
                    let mut inner = Fields::parse(record, super::field::MAX_FIELDS)?;
                    let name = inner.string(tag::NAME, MAX_NAME)?.to_owned();
                    inner.finish()?;
                    check_name(&name)?;
                    Ok(name)
                })
                .collect::<Result<Vec<_>, ProtoError>>()?,
        };
        let body = Self {
            code,
            detail,
            retry_full,
            missing,
            expected: fields.opt_array::<32>(tag::EXPECTED)?,
            actual: fields.opt_array::<32>(tag::ACTUAL)?,
            retry_after_ms: fields.opt_u64(tag::RETRY_AFTER_MS)?,
            owner_client: fields.opt_array::<16>(tag::OWNER_CLIENT)?,
            expires_at_ms: fields.opt_u64(tag::EXPIRES_AT_MS)?,
            reason: fields
                .opt_string(tag::REASON, MAX_DETAIL)?
                .map(str::to_owned),
            dir_path: fields
                .opt_string(tag::DIR_PATH, MAX_PATH)?
                .map(str::to_owned),
            dir_ino: fields.opt_array::<16>(tag::DIR_INO)?,
            epoch: fields.opt_u64(tag::EPOCH)?,
            snapshot_seq: fields.opt_u64(tag::SNAPSHOT_SEQ)?,
            base_seq: fields.opt_u64(tag::BASE_SEQ)?,
            request_base_seq: fields.opt_u64(tag::REQUEST_BASE_SEQ)?,
            dir_version: fields.opt_array::<32>(tag::DIR_VERSION)?,
        };
        fields.finish()?;
        body.validate()?;
        Ok(body)
    }
}
