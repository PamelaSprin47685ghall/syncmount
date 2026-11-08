//! The remote boundary of the shadow filesystem.
//!
//! `P4` implements [`MmRemote`] with the SMM1 HTTP client. The shadow never
//! opens a socket itself. Every request type here carries exactly the state a
//! correct HTTP client needs; response types carry the committed version, not
//! a partial acknowledgement.
//!
//! Errors are classified by cause, not by transport. A `BaseChanged`,
//! `SignatureStale`, `LockHeld`, `LockLost` or `LockExpired` is a conflict the
//! caller reports as `EAGAIN` and retries on the next `fsync`. Everything the
//! caller cannot repair (`Io`, `Internal`, `Unauthenticated`) becomes `EIO`.

use std::fmt;
use std::path::PathBuf;

use crate::mmap::rsync::{Instruction, Signature};
use crate::mmap::types::{
    BatchId, DirAttrs, EntryKind, Hash, Ino, LockId, ManifestEntry, MmBase, MmSeq,
};

/// One direct entry returned by checkout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckoutEntry {
    pub name: String,
    pub ino: Ino,
    pub kind: EntryKind,
    pub attrs: DirAttrs,
    pub size: u64,
    pub file_root: Hash,
    pub content_hash: Option<Hash>,
    pub target: Option<Vec<u8>>,
}

impl CheckoutEntry {
    /// Build a `KEEP` manifest entry from this snapshot entry.
    pub fn manifest_entry(&self, op: crate::mmap::types::EntryOp) -> ManifestEntry {
        ManifestEntry {
            name: self.name.clone(),
            ino: self.ino,
            kind: self.kind,
            op,
            from_name: None,
            mode: self.attrs.mode,
            uid: self.attrs.uid,
            gid: self.attrs.gid,
            mtime_ns: self.attrs.mtime_ns,
            size: self.size,
            file_root: self.file_root,
            content_hash: self.content_hash,
            target: self.target.clone(),
        }
    }
}

/// One file body aligned with a [`CheckoutEntry`] by inode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckoutBody {
    pub ino: Ino,
    pub bytes: Vec<u8>,
}

/// A complete directory snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckoutSnapshot {
    pub dir_ino: Ino,
    pub base: MmBase,
    pub snapshot_seq: MmSeq,
    pub attrs: DirAttrs,
    pub entries: Vec<CheckoutEntry>,
    /// Present only for `bodies = true`. A body may be omitted when the
    /// server knows the client already holds that `file_root`.
    pub bodies: Vec<CheckoutBody>,
}

/// What a checkout produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckoutOutcome {
    /// The caller's base still describes the directory.
    NotModified { base: MmBase, snapshot_seq: MmSeq },
    /// A replacement snapshot, including the current global sequence.
    Snapshot(CheckoutSnapshot),
}

/// One checkout request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckoutRequest {
    pub dir_path: String,
    pub dir_ino: Ino,
    /// `None` forces a full manifest; `bodies` then decides whether file
    /// content is included.
    pub if_base: Option<MmBase>,
    pub if_snapshot: Option<MmSeq>,
    pub bodies: bool,
}

/// One file the caller wants block signatures for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureFile {
    pub name: String,
    pub ino: Ino,
    pub size: u64,
    pub file_root: Hash,
}

/// A signature request against the current base.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignaturesRequest {
    pub dir_path: String,
    pub dir_ino: Ino,
    pub base: MmBase,
    pub files: Vec<SignatureFile>,
}

/// One file's signature answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureFilePlan {
    pub ino: Ino,
    /// `true` when the base `file_root` equals the request's `file_root`.
    pub unchanged: bool,
    /// Present when a delta is possible.
    pub signature: Option<Signature>,
}

/// Signatures for every requested file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignaturesResponse {
    pub base: MmBase,
    pub files: Vec<SignatureFilePlan>,
}

/// One file read, for a file that was not downloaded by checkout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileReadRequest {
    pub dir_path: String,
    pub dir_ino: Ino,
    pub name: String,
    pub ino: Ino,
    pub file_root: Hash,
    pub offset: u64,
    pub len: u32,
}

/// A checked range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileData {
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub range_hash: Hash,
}

/// Begin an upload and reserve one batch id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadBegin {
    pub batch_id: BatchId,
    pub dir_path: String,
    pub dir_ino: Ino,
    pub base: MmBase,
    pub manifest: Vec<ManifestEntry>,
}

/// One uploaded file. `source` is a staging path, never the live shadow
/// object, so a concurrent write cannot change the bytes mid-upload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadFile {
    pub manifest_index: u32,
    pub ino: Ino,
    pub version: u64,
    pub size: u64,
    pub file_root: Hash,
    pub content_hash: Hash,
    pub source: Option<PathBuf>,
    pub instructions: Vec<Instruction>,
    /// The server keeps the current base content and does not read `source`.
    pub unchanged: bool,
}

/// Commit one upload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadCommit {
    pub batch_id: BatchId,
    pub lock_id: LockId,
    pub dir_path: String,
    pub dir_ino: Ino,
    pub base: MmBase,
    pub manifest: Vec<ManifestEntry>,
    pub files: Vec<UploadFile>,
    pub bytes: u64,
}

/// Abort one upload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadAbort {
    pub batch_id: BatchId,
    pub lock_id: LockId,
}

/// One upload operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UploadRequest {
    Begin(UploadBegin),
    Commit(UploadCommit),
    Abort(UploadAbort),
}

/// Plan returned by `Begin`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadPlan {
    pub batch_id: BatchId,
    pub base: MmBase,
    pub expires_at_ms: u64,
}

/// The authoritative result of a commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadResult {
    pub batch_id: BatchId,
    pub base: MmBase,
    pub snapshot_seq: MmSeq,
    pub dir_version: Hash,
    pub entry_count: u32,
    pub bytes: u64,
}

/// One upload response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UploadResponse {
    Plan(UploadPlan),
    Committed(UploadResult),
    Aborted,
}

/// Acquire, renew or release the per-directory upload lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LockRequest {
    Acquire {
        dir_path: String,
        dir_ino: Ino,
        base: MmBase,
        batch_id: Option<BatchId>,
        ttl_ms: u32,
    },
    Renew {
        lock_id: LockId,
        progress_bytes: u64,
        ttl_ms: u32,
    },
    Release {
        lock_id: LockId,
    },
}

/// A granted lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantedLock {
    pub lock_id: LockId,
    pub dir_ino: Ino,
    pub base: MmBase,
    pub expires_at_ms: u64,
}

/// One lock response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LockResponse {
    Granted(GrantedLock),
    Renewed { expires_at_ms: u64 },
    Released,
}

/// A remote failure with a stable local classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemoteError {
    Io(String),
    Unauthenticated,
    NotFound,
    /// `409 BASE_CHANGED`; carries the server's current base.
    BaseChanged {
        current: MmBase,
        snapshot_seq: MmSeq,
    },
    /// `409 SIGNATURE_STALE`.
    SignatureStale,
    /// `409 MANIFEST_INCOMPLETE`.
    ManifestIncomplete {
        missing: Vec<String>,
    },
    /// `409 HASH_MISMATCH` or `SIZE_MISMATCH`.
    HashMismatch {
        name: String,
        retry_full: bool,
    },
    /// `409 BATCH_CONFLICT`.
    BatchConflict,
    /// `423 LOCK_HELD`.
    LockHeld {
        owner: String,
        expires_at_ms: u64,
        retry_after_ms: u64,
    },
    /// `423 LOCK_LOST`.
    LockLost {
        reason: String,
    },
    /// `423 LOCK_EXPIRED`.
    LockExpired,
    /// `413`.
    TooLarge(String),
    /// A request the remote does not implement.
    Unsupported(String),
    /// `500` or a response that violates the contract.
    Internal(String),
}

impl RemoteError {
    /// True for a stateless conflict that the next `fsync` may resolve.
    pub fn is_conflict(&self) -> bool {
        matches!(
            self,
            Self::BaseChanged { .. }
                | Self::SignatureStale
                | Self::ManifestIncomplete { .. }
                | Self::HashMismatch { .. }
                | Self::BatchConflict
                | Self::LockHeld { .. }
                | Self::LockLost { .. }
                | Self::LockExpired
        )
    }

    /// True when the caller must first refresh and rebuild its base.
    pub fn needs_refresh(&self) -> bool {
        matches!(
            self,
            Self::BaseChanged { .. } | Self::SignatureStale | Self::ManifestIncomplete { .. }
        )
    }
}

impl fmt::Display for RemoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(message) => write!(f, "transport: {message}"),
            Self::Unauthenticated => f.write_str("authentication failed"),
            Self::NotFound => f.write_str("remote entry not found"),
            Self::BaseChanged {
                current,
                snapshot_seq,
            } => write!(
                f,
                "base changed (epoch {}, dir_seq {}, snapshot {})",
                current.epoch,
                current.dir_seq.get(),
                snapshot_seq.get()
            ),
            Self::SignatureStale => f.write_str("signature stale"),
            Self::ManifestIncomplete { missing } => {
                write!(f, "manifest incomplete: {missing:?}")
            }
            Self::HashMismatch { name, retry_full } => {
                write!(f, "content mismatch for {name} (retry full: {retry_full})")
            }
            Self::BatchConflict => f.write_str("batch id conflict"),
            Self::LockHeld {
                owner,
                expires_at_ms,
                ..
            } => write!(f, "directory locked by {owner} until {expires_at_ms}"),
            Self::LockLost { reason } => write!(f, "lock lost: {reason}"),
            Self::LockExpired => f.write_str("lock expired"),
            Self::TooLarge(message) => write!(f, "too large: {message}"),
            Self::Unsupported(message) => write!(f, "unsupported: {message}"),
            Self::Internal(message) => write!(f, "remote error: {message}"),
        }
    }
}

impl std::error::Error for RemoteError {}

/// The remote half of the shadow filesystem.
///
/// Implementations must be safe to call from several FUSE worker threads.
pub trait MmRemote: Send + Sync {
    fn checkout(&self, request: &CheckoutRequest) -> Result<CheckoutOutcome, RemoteError>;
    fn signatures(&self, request: &SignaturesRequest) -> Result<SignaturesResponse, RemoteError>;
    fn upload(&self, request: &UploadRequest) -> Result<UploadResponse, RemoteError>;
    fn lock(&self, request: &LockRequest) -> Result<LockResponse, RemoteError>;
    fn file_read(&self, request: &FileReadRequest) -> Result<FileData, RemoteError>;
}
