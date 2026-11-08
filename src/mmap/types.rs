//! Plain value types exchanged with the mm database.
//!
//! These mirror table rows one-to-one. They carry no SQL and no hashing; the
//! canonical encodings live in [`super::base`] and [`super::manifest`].
//!
//! Newtypes keep the two sequence spaces apart: [`DirSeq`] advances only when
//! one directory commits, while [`MmSeq`] advances once per committed batch.
//! There is deliberately no implicit conversion between them.

use std::fmt;

use serde::{Deserialize, Serialize};

/// One 128-bit inode id. The root directory is all zeroes.
pub type Ino = [u8; 16];

/// One 32-byte BLAKE3 digest.
pub type Hash = [u8; 32];

/// One 16-byte authenticated client id.
pub type ClientId = [u8; 16];

/// One 16-byte session id.
pub type SessionId = [u8; 16];

/// The root directory's inode id. All zeroes, as in the 1.0 store.
pub const ROOT_INO: Ino = [0; 16];

/// Permission bits of a freshly created root directory (0755).
pub const ROOT_MODE: u32 = 0o755;

/// Bytes in one content chunk. Matches the 1.0 store and transfer fragment.
pub const CHUNK_BYTES: u32 = 65_536;

/// Which end owns this mm database.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MmRole {
    Server,
    Client,
}

impl MmRole {
    /// The exact text stored in `mm_meta.role`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Client => "client",
        }
    }

    /// Parse the `mm_meta.role` text.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "server" => Some(Self::Server),
            "client" => Some(Self::Client),
            _ => None,
        }
    }
}

impl fmt::Display for MmRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A per-directory sequence. It advances only when that directory commits.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct DirSeq(u64);

impl DirSeq {
    /// The sequence of a directory that has never committed.
    pub const ZERO: Self = Self(0);

    /// Wrap one value. Callers must know which sequence space they hold.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The raw value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for DirSeq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The global mm snapshot sequence. It advances once per committed batch.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct MmSeq(u64);

impl MmSeq {
    /// The sequence before the first committed batch.
    pub const ZERO: Self = Self(0);

    /// Wrap one value. Callers must know which sequence space they hold.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The raw value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for MmSeq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Base version of one directory.
///
/// `epoch` identifies one mm database generation, `dir_seq` is that
/// directory's own sequence, and `dir_version` is the canonical digest of its
/// direct entries. Other directories committing never change this triple.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmBase {
    pub epoch: u64,
    pub dir_seq: DirSeq,
    pub dir_version: Hash,
}

impl MmBase {
    /// Construct one base triple.
    pub const fn new(epoch: u64, dir_seq: DirSeq, dir_version: Hash) -> Self {
        Self {
            epoch,
            dir_seq,
            dir_version,
        }
    }
}

/// Attributes shared by directories and direct entries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirAttrs {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime_ns: i64,
}

/// The kind of one direct entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntryKind {
    File,
    Symlink,
    Dir,
}

impl EntryKind {
    /// The exact text stored in `mm_files.kind` and `mm_base.kind`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Symlink => "symlink",
            Self::Dir => "dir",
        }
    }

    /// Parse the stored kind text.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "file" => Some(Self::File),
            "symlink" => Some(Self::Symlink),
            "dir" => Some(Self::Dir),
            _ => None,
        }
    }

    /// One-byte tag used by the canonical manifest and `dir_version` encodings.
    ///
    /// The values match the 1.1 design: 1 = file, 2 = symlink, 3 = dir.
    pub const fn tag(self) -> u8 {
        match self {
            Self::File => 1,
            Self::Symlink => 2,
            Self::Dir => 3,
        }
    }

    /// Parse the one-byte tag.
    pub const fn parse_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::File),
            2 => Some(Self::Symlink),
            3 => Some(Self::Dir),
            _ => None,
        }
    }

    /// True for a regular file.
    pub const fn is_file(self) -> bool {
        matches!(self, Self::File)
    }

    /// True for a directory.
    pub const fn is_dir(self) -> bool {
        matches!(self, Self::Dir)
    }
}

/// What the manifest asks the server to do with one direct entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntryOp {
    Keep,
    Put,
    Delete,
    Rename,
    DirAdd,
    DirRemove,
    DirRename,
}

impl EntryOp {
    /// One-byte tag used by the canonical manifest encoding.
    ///
    /// The values match the 1.1 design: 1 = KEEP, 2 = PUT, 3 = DELETE,
    /// 4 = RENAME, 5 = DIR_ADD, 6 = DIR_REMOVE, 7 = DIR_RENAME.
    pub const fn tag(self) -> u8 {
        match self {
            Self::Keep => 1,
            Self::Put => 2,
            Self::Delete => 3,
            Self::Rename => 4,
            Self::DirAdd => 5,
            Self::DirRemove => 6,
            Self::DirRename => 7,
        }
    }

    /// Parse the one-byte tag.
    pub const fn parse_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Keep),
            2 => Some(Self::Put),
            3 => Some(Self::Delete),
            4 => Some(Self::Rename),
            5 => Some(Self::DirAdd),
            6 => Some(Self::DirRemove),
            7 => Some(Self::DirRename),
            _ => None,
        }
    }

    /// True for an operation that removes the entry.
    pub const fn is_delete(self) -> bool {
        matches!(self, Self::Delete | Self::DirRemove)
    }

    /// True for an operation that renames the entry.
    pub const fn is_rename(self) -> bool {
        matches!(self, Self::Rename | Self::DirRename)
    }
}

/// State of one row in `mm_uploads`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UploadState {
    Open,
    Uploading,
    Verified,
    Aborted,
}

impl UploadState {
    /// The exact text stored in `mm_uploads.state`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Uploading => "uploading",
            Self::Verified => "verified",
            Self::Aborted => "aborted",
        }
    }

    /// Parse the stored state text.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "open" => Some(Self::Open),
            "uploading" => Some(Self::Uploading),
            "verified" => Some(Self::Verified),
            "aborted" => Some(Self::Aborted),
            _ => None,
        }
    }
}

impl fmt::Display for UploadState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle phase of one directory in `mm_dirs`.
///
/// The server normally stores [`Phase::Ready`]; the other variants let a
/// client-side shadow record the same row shape without inventing a second
/// schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Phase {
    Absent,
    Manifest,
    CheckingOut,
    Ready,
    Stale,
    Failed,
}

impl Phase {
    /// The exact text stored in `mm_dirs.phase`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Manifest => "manifest",
            Self::CheckingOut => "checking_out",
            Self::Ready => "ready",
            Self::Stale => "stale",
            Self::Failed => "failed",
        }
    }

    /// Parse the stored phase text.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "absent" => Some(Self::Absent),
            "manifest" => Some(Self::Manifest),
            "checking_out" => Some(Self::CheckingOut),
            "ready" => Some(Self::Ready),
            "stale" => Some(Self::Stale),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A 16-byte batch id generated by the client.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BatchId([u8; 16]);

impl BatchId {
    /// Wrap an existing 16-byte id.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Generate a non-zero random id.
    pub fn new_random() -> Self {
        loop {
            let bytes = rand::random::<[u8; 16]>();
            if bytes != [0; 16] {
                return Self(bytes);
            }
        }
    }

    /// The raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Lower-case hexadecimal, for logs and test failure messages.
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for BatchId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Display for BatchId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// A 16-byte upload-lock id generated by the server.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LockId([u8; 16]);

impl LockId {
    /// Wrap an existing 16-byte id.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Generate a non-zero random id.
    pub fn new_random() -> Self {
        loop {
            let bytes = rand::random::<[u8; 16]>();
            if bytes != [0; 16] {
                return Self(bytes);
            }
        }
    }

    /// The raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Lower-case hexadecimal, for logs and test failure messages.
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for LockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Display for LockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// One entry of the full direct-entry manifest.
///
/// The record carries every field the server needs to validate and apply the
/// entry. `op` is explicit; the manifest never omits an entry to mean
/// "delete". `content_hash` is the whole-file BLAKE3 used to verify a `PUT`,
/// and `file_root` is the 1.0-compatible chunk-list Merkle root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub name: String,
    pub ino: Ino,
    pub kind: EntryKind,
    pub op: EntryOp,
    pub from_name: Option<String>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime_ns: i64,
    pub size: u64,
    pub file_root: Hash,
    pub content_hash: Option<Hash>,
    pub target: Option<Vec<u8>>,
}

impl ManifestEntry {
    /// True for a directory entry.
    pub const fn is_dir(&self) -> bool {
        self.kind.is_dir()
    }

    /// True for an entry the manifest removes.
    pub const fn is_delete(&self) -> bool {
        self.op.is_delete()
    }
}

/// A row of `mm_dirs`: one directory and its current base triple.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirRecord {
    pub ino: Ino,
    pub path: String,
    pub base: MmBase,
    pub phase: Phase,
    pub attrs: DirAttrs,
    pub deleted: bool,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

/// A row of `mm_files`: one direct entry under one directory.
///
/// A file inode has exactly one name in the mm namespace (hard links are not
/// supported), so `ino` is the primary key and `(dir_ino, name)` is unique.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRecord {
    pub ino: Ino,
    pub dir_ino: Ino,
    pub name: String,
    pub kind: EntryKind,
    pub attrs: DirAttrs,
    pub size: u64,
    pub file_root: Hash,
    pub content_hash: Option<Hash>,
    pub target: Option<Vec<u8>>,
    pub version: u64,
    pub deleted: bool,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl FileRecord {
    /// Build a manifest entry from this row.
    pub fn manifest_entry(&self, op: EntryOp) -> ManifestEntry {
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

/// A row of `mm_versions`: one immutable content version of one file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionRecord {
    pub ino: Ino,
    pub version: u64,
    pub size: u64,
    pub file_root: Hash,
    pub content_hash: Hash,
    pub chunk_count: u32,
    pub created_at_ms: i64,
}

/// A row of `mm_uploads`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadRecord {
    pub batch_id: BatchId,
    pub lock_id: LockId,
    pub dir_path: String,
    pub dir_ino: Ino,
    pub base_epoch: u64,
    pub base_seq: DirSeq,
    pub dir_version: Hash,
    pub manifest_hash: Hash,
    pub state: UploadState,
    pub spool_path: String,
    pub bytes_received: u64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub expires_at_ms: i64,
}

/// A row of `mm_locks`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockRecord {
    pub lock_id: LockId,
    pub dir_path: String,
    pub dir_ino: Ino,
    pub owner_client: ClientId,
    pub owner_session: SessionId,
    pub base_epoch: u64,
    pub base_seq: DirSeq,
    pub batch_id: Option<BatchId>,
    pub expires_at_ms: i64,
    pub created_at_ms: i64,
    pub renewed_at_ms: i64,
    pub progress_bytes: u64,
}

/// A row of `mm_batches`: the immutable commit log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchRecord {
    pub batch_id: BatchId,
    pub dir_path: String,
    pub dir_ino: Ino,
    pub base_epoch: u64,
    pub base_seq: DirSeq,
    pub base_seq_after: DirSeq,
    pub snapshot_seq: MmSeq,
    pub dir_version_before: Hash,
    pub dir_version_after: Hash,
    pub manifest_hash: Hash,
    pub client_id: ClientId,
    pub entry_count: u32,
    pub bytes: u64,
    pub committed_at_ms: i64,
}

/// A row of `mm_dir_versions`: the authoritative per-directory base.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirVersionRecord {
    pub dir_ino: Ino,
    pub dir_path: String,
    pub base_epoch: u64,
    pub dir_seq: DirSeq,
    pub snapshot_seq: MmSeq,
    pub dir_version: Hash,
    pub updated_at_ms: i64,
}

/// Validate one directory entry name.
///
/// Names are single path components: 1..=255 bytes, no `/`, no NUL, and not
/// `.` or `..`.
pub fn validate_name(name: &str) -> Result<(), &'static str> {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return Err("name is empty");
    }
    if bytes.len() > 255 {
        return Err("name is longer than 255 bytes");
    }
    if name == "." || name == ".." {
        return Err("name is a reserved component");
    }
    if name.contains('/') {
        return Err("name contains '/'");
    }
    if bytes.contains(&0) {
        return Err("name contains NUL");
    }
    Ok(())
}

/// Validate one canonical absolute directory path.
///
/// A path starts with `/`, is at most 4096 bytes, has no empty or `.`/`..`
/// component, and has no trailing `/` except for the root itself.
pub fn validate_dir_path(path: &str) -> Result<(), &'static str> {
    if path.is_empty() {
        return Err("path is empty");
    }
    if path.len() > 4096 {
        return Err("path is longer than 4096 bytes");
    }
    if !path.starts_with('/') {
        return Err("path is not absolute");
    }
    if path.as_bytes().contains(&0) {
        return Err("path contains NUL");
    }
    if path != "/" && path.ends_with('/') {
        return Err("path has a trailing slash");
    }
    if path.contains("//") {
        return Err("path has an empty component");
    }
    for component in path.split('/') {
        if component == "." || component == ".." {
            return Err("path has a dot component");
        }
    }
    Ok(())
}

/// Validate one mm namespace name, such as `/private-mm`.
pub fn validate_namespace(namespace: &str) -> Result<(), &'static str> {
    if namespace.len() < 2 {
        return Err("namespace is empty");
    }
    if namespace.len() > 255 {
        return Err("namespace is longer than 255 bytes");
    }
    if !namespace.starts_with('/') {
        return Err("namespace is not absolute");
    }
    if namespace.ends_with('/') {
        return Err("namespace has a trailing slash");
    }
    if namespace.as_bytes().contains(&0) {
        return Err("namespace contains NUL");
    }
    if namespace.contains("//") {
        return Err("namespace has an empty component");
    }
    for component in namespace.split('/') {
        if component == "." || component == ".." {
            return Err("namespace has a dot component");
        }
    }
    Ok(())
}
