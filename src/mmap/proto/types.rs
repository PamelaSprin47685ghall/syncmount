//! Records shared by the SMM1 messages.
//!
//! Everything here is a *wire* value. It deliberately has no dependency on
//! `mmap::types`, `mmap::manifest` or `mmap::base`; the conversion boundary is
//! [`MmBaseWire`] / [`ManifestEntryWire`] plus the [`ManifestEntrySource`]
//! trait. P1A's own types implement those conversions when they land, which
//! keeps the wire format stable even if the database records evolve.

use super::error::ProtoError;
use super::field::{FieldWriter, Fields};
use super::limits::Limits;
use super::tag;

/// Largest canonical directory path.
pub const MAX_PATH: usize = 4096;
/// Largest single path component.
pub const MAX_NAME: usize = 255;
/// Largest namespace label.
pub const MAX_NAMESPACE: usize = 255;
/// Largest symlink target.
pub const MAX_TARGET: usize = 4096;
/// Largest error detail or reason.
pub const MAX_DETAIL: usize = 512;
/// Smallest rsync block.
pub const MIN_BLOCK_SIZE: u32 = 1024;
/// Largest rsync block.
pub const MAX_BLOCK_SIZE: u32 = 1024 * 1024;
/// Largest literal instruction.
pub const MAX_LITERAL: u32 = 8 * 1024 * 1024;

/// Validate a canonical absolute directory path.
///
/// A path is absolute, has no empty, `.` or `..` component, no repeated `/`,
/// no trailing `/` (except the root) and at most [`MAX_PATH`] bytes.
///
/// # Errors
///
/// [`ProtoError::Inconsistent`] or [`ProtoError::ValueOutOfRange`].
pub fn check_path(path: &str) -> Result<(), ProtoError> {
    if path.is_empty() || !path.starts_with('/') {
        return Err(ProtoError::Inconsistent("path is not absolute"));
    }
    if path.as_bytes().contains(&0) {
        return Err(ProtoError::Inconsistent("path contains NUL"));
    }
    if path == "/" {
        return Ok(());
    }
    if path.len() > MAX_PATH {
        return Err(ProtoError::ValueOutOfRange {
            tag: tag::DIR_PATH,
            value: path.len() as u64,
            max: MAX_PATH as u64,
        });
    }
    if path != "/" && path.ends_with('/') {
        return Err(ProtoError::Inconsistent("path has a trailing slash"));
    }
    for part in path.split('/').skip(1) {
        if part.is_empty() || part == "." || part == ".." {
            return Err(ProtoError::Inconsistent("path component is not canonical"));
        }
    }
    Ok(())
}

/// Validate one path component.
///
/// # Errors
///
/// [`ProtoError::Inconsistent`] or [`ProtoError::ValueOutOfRange`].
pub fn check_name(name: &str) -> Result<(), ProtoError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.as_bytes().contains(&0)
    {
        return Err(ProtoError::Inconsistent("name is not a single component"));
    }
    if name.len() > MAX_NAME {
        return Err(ProtoError::ValueOutOfRange {
            tag: tag::NAME,
            value: name.len() as u64,
            max: MAX_NAME as u64,
        });
    }
    Ok(())
}

/// Validate a namespace label.
///
/// # Errors
///
/// [`ProtoError::Inconsistent`] or [`ProtoError::ValueOutOfRange`].
pub fn check_namespace(namespace: &str) -> Result<(), ProtoError> {
    if namespace.is_empty() || namespace.len() > MAX_NAMESPACE {
        return Err(ProtoError::ValueOutOfRange {
            tag: tag::NAMESPACE,
            value: namespace.len() as u64,
            max: MAX_NAMESPACE as u64,
        });
    }
    if namespace.contains('/') || namespace.contains('\0') {
        return Err(ProtoError::Inconsistent("namespace contains a separator"));
    }
    Ok(())
}

/// The kind of a direct entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EntryKind {
    /// Regular file.
    File = 1,
    /// Symbolic link.
    Symlink = 2,
    /// Directory.
    Dir = 3,
}

impl EntryKind {
    /// Decode the wire byte.
    ///
    /// # Errors
    ///
    /// [`ProtoError::BadEnum`].
    pub const fn from_u8(raw: u8) -> Result<Self, ProtoError> {
        match raw {
            1 => Ok(Self::File),
            2 => Ok(Self::Symlink),
            3 => Ok(Self::Dir),
            other => Err(ProtoError::BadEnum {
                tag: tag::ENTRY_KIND,
                value: other as u64,
            }),
        }
    }

    /// The wire byte.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// What a manifest entry does to the directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EntryOp {
    /// Keep the current object.
    Keep = 1,
    /// Put new content or a new object.
    Put = 2,
    /// Delete the object.
    Delete = 3,
    /// Rename within the directory.
    Rename = 4,
    /// Create an empty child directory.
    DirAdd = 5,
    /// Remove an empty child directory.
    DirRemove = 6,
    /// Rename a child directory within the directory.
    DirRename = 7,
}

impl EntryOp {
    /// Decode the wire byte.
    ///
    /// # Errors
    ///
    /// [`ProtoError::BadEnum`].
    pub const fn from_u8(raw: u8) -> Result<Self, ProtoError> {
        match raw {
            1 => Ok(Self::Keep),
            2 => Ok(Self::Put),
            3 => Ok(Self::Delete),
            4 => Ok(Self::Rename),
            5 => Ok(Self::DirAdd),
            6 => Ok(Self::DirRemove),
            7 => Ok(Self::DirRename),
            other => Err(ProtoError::BadEnum {
                tag: tag::OP,
                value: other as u64,
            }),
        }
    }

    /// The wire byte.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Whether the op acts on a directory structure entry.
    pub const fn is_structural(self) -> bool {
        matches!(self, Self::DirAdd | Self::DirRemove | Self::DirRename)
    }
}

/// One item of an upload plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PlanAction {
    /// No data movement.
    Keep = 1,
    /// Send a delta against the base.
    PutDelta = 2,
    /// Send the whole file.
    PutFull = 3,
    /// Remove an entry.
    Delete = 4,
    /// Rename an entry.
    Rename = 5,
    /// Create a child directory.
    DirAdd = 6,
    /// Remove an empty child directory.
    DirRemove = 7,
    /// Rename a child directory.
    DirRename = 8,
}

impl PlanAction {
    /// Decode the wire byte.
    ///
    /// # Errors
    ///
    /// [`ProtoError::BadEnum`].
    pub const fn from_u8(raw: u8) -> Result<Self, ProtoError> {
        match raw {
            1 => Ok(Self::Keep),
            2 => Ok(Self::PutDelta),
            3 => Ok(Self::PutFull),
            4 => Ok(Self::Delete),
            5 => Ok(Self::Rename),
            6 => Ok(Self::DirAdd),
            7 => Ok(Self::DirRemove),
            8 => Ok(Self::DirRename),
            other => Err(ProtoError::BadEnum {
                tag: tag::OP,
                value: other as u64,
            }),
        }
    }

    /// The wire byte.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Signature state of one file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SignatureState {
    /// Client's `local_file_root` equals the base.
    Unchanged = 1,
    /// Blocks follow.
    Delta = 2,
    /// No usable base; send the whole file.
    Full = 3,
}

impl SignatureState {
    /// Decode the wire byte.
    ///
    /// # Errors
    ///
    /// [`ProtoError::BadEnum`].
    pub const fn from_u8(raw: u8) -> Result<Self, ProtoError> {
        match raw {
            1 => Ok(Self::Unchanged),
            2 => Ok(Self::Delta),
            3 => Ok(Self::Full),
            other => Err(ProtoError::BadEnum {
                tag: tag::SIGNATURE_STATE,
                value: other as u64,
            }),
        }
    }

    /// The wire byte.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Upload mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum UploadMode {
    /// Use rsync signatures.
    Delta = 1,
    /// Send every file whole.
    Full = 2,
}

impl UploadMode {
    /// Decode the wire value.
    ///
    /// # Errors
    ///
    /// [`ProtoError::BadEnum`].
    pub const fn from_u32(raw: u32) -> Result<Self, ProtoError> {
        match raw {
            1 => Ok(Self::Delta),
            2 => Ok(Self::Full),
            other => Err(ProtoError::BadEnum {
                tag: tag::MODE,
                value: other as u64,
            }),
        }
    }

    /// The wire value.
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Lifecycle of a batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BatchState {
    /// Begun, not committed.
    Open = 1,
    /// Committed successfully.
    Committed = 2,
    /// Aborted.
    Aborted = 3,
}

impl BatchState {
    /// Decode the wire byte.
    ///
    /// # Errors
    ///
    /// [`ProtoError::BadEnum`].
    pub const fn from_u8(raw: u8) -> Result<Self, ProtoError> {
        match raw {
            1 => Ok(Self::Open),
            2 => Ok(Self::Committed),
            3 => Ok(Self::Aborted),
            other => Err(ProtoError::BadEnum {
                tag: tag::BATCH_STATE,
                value: other as u64,
            }),
        }
    }

    /// The wire byte.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Directory attributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirAttrs {
    /// Permission bits.
    pub mode: u32,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// Modification time.
    pub mtime_ns: u64,
}

impl DirAttrs {
    pub(super) fn encode_into(self, writer: &mut FieldWriter, tag: u8) -> Result<(), ProtoError> {
        writer.nested(tag, |inner| {
            inner.u32(tag::MODE, self.mode)?;
            inner.u32(tag::UID, self.uid)?;
            inner.u32(tag::GID, self.gid)?;
            inner.u64(tag::MTIME_NS, self.mtime_ns)
        })
    }

    pub(super) fn decode_from(mut fields: Fields<'_>) -> Result<Self, ProtoError> {
        let attrs = Self {
            mode: fields.u32(tag::MODE)?,
            uid: fields.u32(tag::UID)?,
            gid: fields.u32(tag::GID)?,
            mtime_ns: fields.u64(tag::MTIME_NS)?,
        };
        fields.finish()?;
        Ok(attrs)
    }
}

/// One direct entry in a manifest or snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Single path component.
    pub name: String,
    /// Inode, when known.
    pub ino: Option<[u8; 16]>,
    /// File, symlink or directory.
    pub kind: EntryKind,
    /// Operation.
    pub op: EntryOp,
    /// Rename source name.
    pub from_name: Option<String>,
    /// Permission bits.
    pub mode: u32,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// Modification time.
    pub mtime_ns: u64,
    /// Size in bytes.
    pub size: u64,
    /// 64 KiB-chunk Merkle root.
    pub file_root: Option<[u8; 32]>,
    /// Whole-file BLAKE3.
    pub content_hash: Option<[u8; 32]>,
    /// Symlink target bytes.
    pub target: Option<Vec<u8>>,
}

impl Entry {
    /// Encode this entry as one list record.
    ///
    /// # Errors
    ///
    /// Any field width or validation error.
    pub fn encode_record(&self) -> Result<Vec<u8>, ProtoError> {
        self.validate_basic()?;
        let mut writer = FieldWriter::new();
        writer.string(tag::NAME, &self.name)?;
        if let Some(ino) = self.ino {
            writer.array(tag::INO, &ino)?;
        }
        writer.u8(tag::ENTRY_KIND, self.kind.as_u8())?;
        writer.u8(tag::OP, self.op.as_u8())?;
        if let Some(from) = &self.from_name {
            writer.string(tag::FROM_NAME, from)?;
        }
        writer.u32(tag::MODE, self.mode)?;
        writer.u32(tag::UID, self.uid)?;
        writer.u32(tag::GID, self.gid)?;
        writer.u64(tag::MTIME_NS, self.mtime_ns)?;
        writer.u64(tag::SIZE, self.size)?;
        if let Some(root) = self.file_root {
            writer.array(tag::FILE_ROOT, &root)?;
        }
        if let Some(hash) = self.content_hash {
            writer.array(tag::CONTENT_HASH, &hash)?;
        }
        if let Some(target) = &self.target {
            writer.raw(tag::TARGET, target)?;
        }
        Ok(writer.into_bytes())
    }

    /// Decode one list record.
    ///
    /// # Errors
    ///
    /// Structural, width or basic validation errors.
    pub fn decode_record(bytes: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(bytes, super::field::MAX_FIELDS)?;
        let name = fields.string(tag::NAME, MAX_NAME)?.to_owned();
        let ino = fields.opt_array::<16>(tag::INO)?;
        let kind = EntryKind::from_u8(fields.u8(tag::ENTRY_KIND)?)?;
        let op = EntryOp::from_u8(fields.u8(tag::OP)?)?;
        let from_name = fields
            .opt_string(tag::FROM_NAME, MAX_NAME)?
            .map(str::to_owned);
        let mode = fields.u32(tag::MODE)?;
        let uid = fields.u32(tag::UID)?;
        let gid = fields.u32(tag::GID)?;
        let mtime_ns = fields.u64(tag::MTIME_NS)?;
        let size = fields.u64(tag::SIZE)?;
        let file_root = fields.opt_array::<32>(tag::FILE_ROOT)?;
        let content_hash = fields.opt_array::<32>(tag::CONTENT_HASH)?;
        let target = fields.opt(tag::TARGET).map(<[u8]>::to_vec);
        fields.finish()?;
        let entry = Self {
            name,
            ino,
            kind,
            op,
            from_name,
            mode,
            uid,
            gid,
            mtime_ns,
            size,
            file_root,
            content_hash,
            target,
        };
        entry.validate_basic()?;
        Ok(entry)
    }

    /// Check the rules that do not depend on manifest-vs-snapshot context.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Inconsistent`] or [`ProtoError::ValueOutOfRange`].
    pub fn validate_basic(&self) -> Result<(), ProtoError> {
        check_name(&self.name)?;
        if let Some(from) = &self.from_name {
            check_name(from)?;
        }
        if self.size > Limits::new().max_file_size && self.kind != EntryKind::Dir {
            return Err(ProtoError::ValueOutOfRange {
                tag: tag::SIZE,
                value: self.size,
                max: Limits::new().max_file_size,
            });
        }
        match self.kind {
            EntryKind::Dir => {
                if self.size != 0 {
                    return Err(ProtoError::Inconsistent("directory has a size"));
                }
                if self.content_hash.is_some() || self.target.is_some() {
                    return Err(ProtoError::Inconsistent("directory carries content fields"));
                }
                if matches!(self.op, EntryOp::Put | EntryOp::Rename | EntryOp::Delete) {
                    return Err(ProtoError::Inconsistent("directory uses a file op"));
                }
                if self.op == EntryOp::DirRename && self.from_name.is_none() {
                    return Err(ProtoError::Inconsistent("DIR_RENAME lacks from_name"));
                }
                if !matches!(
                    self.op,
                    EntryOp::Keep | EntryOp::DirAdd | EntryOp::DirRemove | EntryOp::DirRename
                ) {
                    return Err(ProtoError::Inconsistent("directory op is invalid"));
                }
            }
            EntryKind::File | EntryKind::Symlink => {
                if self.op.is_structural() {
                    return Err(ProtoError::Inconsistent("file uses a directory op"));
                }
                if self.kind == EntryKind::Symlink {
                    if let Some(target) = &self.target {
                        if target.is_empty() || target.len() > MAX_TARGET {
                            return Err(ProtoError::ValueOutOfRange {
                                tag: tag::TARGET,
                                value: target.len() as u64,
                                max: MAX_TARGET as u64,
                            });
                        }
                        if self.size != target.len() as u64 {
                            return Err(ProtoError::Inconsistent(
                                "symlink size differs from target",
                            ));
                        }
                    }
                    if self.content_hash.is_some() {
                        return Err(ProtoError::Inconsistent("symlink carries content_hash"));
                    }
                } else {
                    if self.target.is_some() {
                        return Err(ProtoError::Inconsistent("regular file carries a target"));
                    }
                    if self.content_hash.is_none() && self.op == EntryOp::Put {
                        return Err(ProtoError::Inconsistent("PUT file lacks content_hash"));
                    }
                }
                if self.op == EntryOp::Delete
                    && (self.file_root.is_some() || self.content_hash.is_some())
                {
                    return Err(ProtoError::Inconsistent("DELETE carries content"));
                }
                if matches!(self.op, EntryOp::Keep | EntryOp::Rename)
                    && (self.ino.is_none() || self.file_root.is_none())
                {
                    return Err(ProtoError::Inconsistent(
                        "KEEP/RENAME lacks ino or file_root",
                    ));
                }
                if self.op == EntryOp::Rename && self.from_name.is_none() {
                    return Err(ProtoError::Inconsistent("RENAME lacks from_name"));
                }
                if let Some(from) = &self.from_name {
                    if from == &self.name {
                        return Err(ProtoError::Inconsistent("rename source equals target"));
                    }
                }
            }
        }
        Ok(())
    }

    /// Additional rules for an entry inside `UPLOAD_BEGIN.entries`.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Inconsistent`].
    pub fn validate_manifest(&self) -> Result<(), ProtoError> {
        self.validate_basic()?;
        if self.kind == EntryKind::Symlink && self.op == EntryOp::Put {
            // A new symlink needs its target; content_hash is not defined.
            if self.target.is_none() {
                return Err(ProtoError::Inconsistent("PUT symlink lacks target"));
            }
        }
        Ok(())
    }

    /// Additional rules for an entry inside `SNAPSHOT.entries`.
    ///
    /// A snapshot describes the current tree, so it always carries an inode,
    /// a file root and, for a symlink, the target.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Inconsistent`].
    pub fn validate_snapshot(&self) -> Result<(), ProtoError> {
        self.validate_basic()?;
        if self.op != EntryOp::Keep {
            return Err(ProtoError::Inconsistent("snapshot entry is not KEEP"));
        }
        if self.ino.is_none() || self.file_root.is_none() {
            return Err(ProtoError::Inconsistent(
                "snapshot entry lacks ino or file_root",
            ));
        }
        if self.kind == EntryKind::Symlink && self.target.is_none() {
            return Err(ProtoError::Inconsistent("snapshot symlink lacks target"));
        }
        Ok(())
    }

    /// The P1A-facing view of this entry.
    pub fn manifest_entry(&self) -> ManifestEntryWire {
        ManifestEntryWire {
            name: self.name.clone(),
            ino: self.ino,
            kind: self.kind,
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            mtime_ns: self.mtime_ns,
            size: self.size,
            file_root: self.file_root,
            content_hash: self.content_hash,
            target: self.target.clone(),
        }
    }

    /// Build a wire entry from a P1A-shaped manifest entry.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Inconsistent`] when the op and source disagree.
    pub fn from_source<S: ManifestEntrySource>(
        source: &S,
        op: EntryOp,
    ) -> Result<Self, ProtoError> {
        let entry = Self {
            name: source.name().to_owned(),
            ino: source.ino(),
            kind: source.kind(),
            op,
            from_name: None,
            mode: source.mode(),
            uid: source.uid(),
            gid: source.gid(),
            mtime_ns: source.mtime_ns(),
            size: source.size(),
            file_root: source.file_root(),
            content_hash: source.content_hash(),
            target: source.target().map(<[u8]>::to_vec),
        };
        entry.validate_basic()?;
        Ok(entry)
    }
}

/// A P1A `ManifestEntry`-shaped source.
///
/// `mmap::types` implements this once its `ManifestEntry` lands. The wire
/// module never names that type, so neither side can drag the other into a
/// dependency cycle.
pub trait ManifestEntrySource {
    /// Single path component.
    fn name(&self) -> &str;
    /// Inode, when known.
    fn ino(&self) -> Option<[u8; 16]>;
    /// Entry kind.
    fn kind(&self) -> EntryKind;
    /// Permission bits.
    fn mode(&self) -> u32;
    /// Owner uid.
    fn uid(&self) -> u32;
    /// Owner gid.
    fn gid(&self) -> u32;
    /// Modification time.
    fn mtime_ns(&self) -> u64;
    /// Size in bytes.
    fn size(&self) -> u64;
    /// 64 KiB-chunk Merkle root.
    fn file_root(&self) -> Option<[u8; 32]>;
    /// Whole-file BLAKE3.
    fn content_hash(&self) -> Option<[u8; 32]>;
    /// Symlink target bytes.
    fn target(&self) -> Option<&[u8]>;
}

/// The P1A-facing shape of one manifest entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestEntryWire {
    /// Single path component.
    pub name: String,
    /// Inode, when known.
    pub ino: Option<[u8; 16]>,
    /// Entry kind.
    pub kind: EntryKind,
    /// Permission bits.
    pub mode: u32,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// Modification time.
    pub mtime_ns: u64,
    /// Size in bytes.
    pub size: u64,
    /// 64 KiB-chunk Merkle root.
    pub file_root: Option<[u8; 32]>,
    /// Whole-file BLAKE3.
    pub content_hash: Option<[u8; 32]>,
    /// Symlink target bytes.
    pub target: Option<Vec<u8>>,
}

impl From<&Entry> for ManifestEntryWire {
    fn from(entry: &Entry) -> Self {
        entry.manifest_entry()
    }
}

/// The P1A-facing shape of the base version triple.
///
/// P1A's `MmBase` should implement `From<MmBaseWire>` (or `TryFrom`) when it
/// lands. Until then this type is the explicit boundary and is exercised by
/// the unit tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmBaseWire {
    /// Database epoch.
    pub epoch: u64,
    /// Per-directory `dir_seq`.
    pub base_seq: u64,
    /// Global `mm_seq`.
    pub snapshot_seq: u64,
    /// Directory inode.
    pub dir_ino: [u8; 16],
    /// Directory version.
    pub dir_version: [u8; 32],
}

/// One rsync block signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockSignature {
    /// Rolling weak checksum.
    pub weak: u32,
    /// Strong BLAKE3-128 checksum (the first 16 bytes of BLAKE3).
    pub strong: [u8; 16],
    /// Block length.
    pub block_len: u32,
}

impl BlockSignature {
    pub(super) fn encode_record(&self) -> Result<Vec<u8>, ProtoError> {
        if self.block_len == 0 {
            return Err(ProtoError::Inconsistent("zero block length"));
        }
        let mut writer = FieldWriter::new();
        writer.u32(tag::WEAK, self.weak)?;
        writer.array(tag::STRONG, &self.strong)?;
        writer.u32(tag::BLOCK_LEN, self.block_len)?;
        Ok(writer.into_bytes())
    }

    pub(super) fn decode_record(bytes: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(bytes, super::field::MAX_FIELDS)?;
        let block = Self {
            weak: fields.u32(tag::WEAK)?,
            strong: fields.array(tag::STRONG)?,
            block_len: fields.u32(tag::BLOCK_LEN)?,
        };
        fields.finish()?;
        if block.block_len == 0 {
            return Err(ProtoError::Inconsistent("zero block length"));
        }
        Ok(block)
    }
}

/// One file in a signature request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureFile {
    /// File name.
    pub name: String,
    /// Inode, when known.
    pub ino: Option<[u8; 16]>,
    /// Local size.
    pub size: u64,
    /// Local 64 KiB Merkle root.
    pub local_file_root: [u8; 32],
}

impl SignatureFile {
    pub(super) fn encode_record(&self) -> Result<Vec<u8>, ProtoError> {
        check_name(&self.name)?;
        let mut writer = FieldWriter::new();
        writer.string(tag::NAME, &self.name)?;
        if let Some(ino) = self.ino {
            writer.array(tag::INO, &ino)?;
        }
        writer.u64(tag::SIZE, self.size)?;
        writer.array(tag::FILE_ROOT, &self.local_file_root)?;
        Ok(writer.into_bytes())
    }

    pub(super) fn decode_record(bytes: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(bytes, super::field::MAX_FIELDS)?;
        let file = Self {
            name: fields.string(tag::NAME, MAX_NAME)?.to_owned(),
            ino: fields.opt_array::<16>(tag::INO)?,
            size: fields.u64(tag::SIZE)?,
            local_file_root: fields.array(tag::FILE_ROOT)?,
        };
        fields.finish()?;
        check_name(&file.name)?;
        Ok(file)
    }
}

/// One file in a signature response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileSignature {
    /// File name.
    pub name: String,
    /// Inode.
    pub ino: [u8; 16],
    /// Base size.
    pub size: u64,
    /// Base 64 KiB Merkle root.
    pub file_root: [u8; 32],
    /// Signature state.
    pub state: SignatureState,
    /// Block size.
    pub block_size: u32,
    /// Block count.
    pub block_count: u32,
    /// Blocks; empty unless `state == Delta`.
    pub blocks: Vec<BlockSignature>,
}

impl FileSignature {
    pub(super) fn encode_record(&self) -> Result<Vec<u8>, ProtoError> {
        self.validate()?;
        let records = self
            .blocks
            .iter()
            .map(BlockSignature::encode_record)
            .collect::<Result<Vec<_>, _>>()?;
        let mut writer = FieldWriter::new();
        writer.string(tag::NAME, &self.name)?;
        writer.array(tag::INO, &self.ino)?;
        writer.u64(tag::SIZE, self.size)?;
        writer.array(tag::FILE_ROOT, &self.file_root)?;
        writer.u8(tag::SIGNATURE_STATE, self.state.as_u8())?;
        writer.u32(tag::BLOCK_SIZE, self.block_size)?;
        writer.u32(tag::BLOCK_COUNT, self.block_count)?;
        writer.list(tag::BLOCKS, Limits::new().max_blocks, &records)?;
        Ok(writer.into_bytes())
    }

    pub(super) fn decode_record(bytes: &[u8]) -> Result<Self, ProtoError> {
        let limits = Limits::new();
        let mut fields = Fields::parse(bytes, super::field::MAX_FIELDS)?;
        let name = fields.string(tag::NAME, MAX_NAME)?.to_owned();
        let ino = fields.array(tag::INO)?;
        let size = fields.u64(tag::SIZE)?;
        let file_root = fields.array(tag::FILE_ROOT)?;
        let state = SignatureState::from_u8(fields.u8(tag::SIGNATURE_STATE)?)?;
        let block_size = fields.u32(tag::BLOCK_SIZE)?;
        let block_count = fields.u32(tag::BLOCK_COUNT)?;
        let records = fields.list(tag::BLOCKS, limits.max_blocks)?;
        fields.finish()?;
        let blocks = records
            .iter()
            .map(|record| BlockSignature::decode_record(record))
            .collect::<Result<Vec<_>, _>>()?;
        let signature = Self {
            name,
            ino,
            size,
            file_root,
            state,
            block_size,
            block_count,
            blocks,
        };
        signature.validate()?;
        Ok(signature)
    }

    /// Check the state/blocks invariants.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Inconsistent`] or [`ProtoError::ValueOutOfRange`].
    pub fn validate(&self) -> Result<(), ProtoError> {
        check_name(&self.name)?;
        let limits = Limits::new();
        if self.block_count > limits.max_blocks {
            return Err(ProtoError::TooManyRecords {
                tag: tag::BLOCKS,
                count: self.block_count,
                cap: limits.max_blocks,
            });
        }
        match self.state {
            SignatureState::Unchanged | SignatureState::Full => {
                if !self.blocks.is_empty() || self.block_count != 0 {
                    return Err(ProtoError::Inconsistent("non-delta carries blocks"));
                }
            }
            SignatureState::Delta => {
                if !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&self.block_size) {
                    return Err(ProtoError::ValueOutOfRange {
                        tag: tag::BLOCK_SIZE,
                        value: u64::from(self.block_size),
                        max: u64::from(MAX_BLOCK_SIZE),
                    });
                }
                if self.block_count as usize != self.blocks.len() {
                    return Err(ProtoError::Inconsistent("block count differs from list"));
                }
                for block in &self.blocks {
                    if block.block_len == 0 || block.block_len > self.block_size {
                        return Err(ProtoError::Inconsistent("block length out of range"));
                    }
                }
            }
        }
        Ok(())
    }
}

/// One item of an upload plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanItem {
    /// Planned action.
    pub action: PlanAction,
    /// Entry name.
    pub name: String,
    /// Diagnostic reason.
    pub reason: Option<String>,
}

impl PlanItem {
    pub(super) fn encode_record(&self) -> Result<Vec<u8>, ProtoError> {
        check_name(&self.name)?;
        let mut writer = FieldWriter::new();
        writer.u8(tag::OP, self.action.as_u8())?;
        writer.string(tag::NAME, &self.name)?;
        if let Some(reason) = &self.reason {
            writer.string(tag::REASON, reason)?;
        }
        Ok(writer.into_bytes())
    }

    pub(super) fn decode_record(bytes: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(bytes, super::field::MAX_FIELDS)?;
        let item = Self {
            action: PlanAction::from_u8(fields.u8(tag::OP)?)?,
            name: fields.string(tag::NAME, MAX_NAME)?.to_owned(),
            reason: fields
                .opt_string(tag::REASON, MAX_DETAIL)?
                .map(str::to_owned),
        };
        fields.finish()?;
        check_name(&item.name)?;
        Ok(item)
    }
}

/// Encode a list of entries into a `FieldWriter` list field.
pub(crate) fn encode_entry_list(
    writer: &mut FieldWriter,
    tag: u8,
    cap: u32,
    entries: &[Entry],
) -> Result<(), ProtoError> {
    if entries.len() > cap as usize {
        return Err(ProtoError::TooManyRecords {
            tag,
            count: entries.len() as u32,
            cap,
        });
    }
    let records = entries
        .iter()
        .map(Entry::encode_record)
        .collect::<Result<Vec<_>, _>>()?;
    writer.list(tag, cap, &records)
}

/// Decode a list of entries.
pub(crate) fn decode_entry_list(records: &[&[u8]], cap: u32) -> Result<Vec<Entry>, ProtoError> {
    if records.len() > cap as usize {
        return Err(ProtoError::TooManyRecords {
            tag: tag::ENTRIES,
            count: records.len() as u32,
            cap,
        });
    }
    records.iter().map(|r| Entry::decode_record(r)).collect()
}
