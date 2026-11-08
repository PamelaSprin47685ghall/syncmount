//! Request and response messages, part one: hello, checkout and read paths.
//!
//! Every message implements [`Message`]. `decode_meta` is strict: it checks
//! the record's own allowed tags, every width, every enum, the context rules
//! (`manifest` vs `snapshot`, signature state vs block list) and the local
//! size caps. A value that passes is safe for the store layer to trust.

use super::error::ProtoError;
use super::field::{FieldWriter, Fields};
use super::header::{HEADER_LEN, Header};
use super::kind::Kind;
use super::limits::Limits;
use super::tag;
use super::types::{
    BlockSignature, DirAttrs, Entry, FileSignature, MAX_DETAIL, MAX_NAME, MAX_PATH, SignatureFile,
    check_name, check_namespace, check_path, decode_entry_list, encode_entry_list,
};

/// A typed SMM1 message body.
pub trait Message: Sized {
    /// The kind this type requires.
    const KIND: Kind;

    /// Encode the tagged meta stream.
    ///
    /// # Errors
    ///
    /// Any field encoding or semantic validation error.
    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError>;

    /// Decode a tagged meta stream.
    ///
    /// # Errors
    ///
    /// Any structural, width, enum or semantic validation error.
    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError>;
}

/// Decode `meta` as `M`, checking the header kind and length.
///
/// # Errors
///
/// [`ProtoError::WrongKind`], [`ProtoError::Truncated`] or any
/// [`Message::decode_meta`] error.
pub fn decode_frame<M: Message>(header: &Header, meta: &[u8]) -> Result<M, ProtoError> {
    if header.kind != M::KIND {
        return Err(ProtoError::WrongKind {
            expected: M::KIND.as_u8(),
            got: header.kind.as_u8(),
        });
    }
    if header.meta_len as usize != meta.len() {
        return Err(ProtoError::Truncated {
            need: header.meta_len as usize,
            got: meta.len(),
        });
    }
    M::decode_meta(meta)
}

/// Encode `message` into a header plus meta stream.
///
/// # Errors
///
/// Any [`Message::encode_meta`] error or an oversized meta stream.
pub fn encode_frame<M: Message>(
    message: &M,
    limits: &Limits,
) -> Result<(Header, Vec<u8>), ProtoError> {
    let meta = message.encode_meta()?;
    let meta_len = u32::try_from(meta.len()).map_err(|_| ProtoError::MetaTooLarge {
        len: meta.len() as u64,
        cap: u64::from(limits.max_meta_len),
    })?;
    let header = Header::new(M::KIND, meta_len, 0, limits)?;
    Ok((header, meta))
}

/// `HELLO`: the client proves knowledge of `K_hello`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    /// Stable client id.
    pub client_id: [u8; 16],
    /// 32-byte client nonce.
    pub client_nonce: [u8; 32],
    /// Client clock in milliseconds.
    pub timestamp_ms: u64,
    /// Keyed proof.
    pub proof: [u8; 32],
}

impl Message for Hello {
    const KIND: Kind = Kind::Hello;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        let mut writer = FieldWriter::new();
        writer.array(tag::CLIENT_ID, &self.client_id)?;
        writer.array(tag::CLIENT_NONCE, &self.client_nonce)?;
        writer.u64(tag::TIMESTAMP_MS, self.timestamp_ms)?;
        writer.array(tag::PROOF, &self.proof)?;
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let hello = Self {
            client_id: fields.array(tag::CLIENT_ID)?,
            client_nonce: fields.array(tag::CLIENT_NONCE)?,
            timestamp_ms: fields.u64(tag::TIMESTAMP_MS)?,
            proof: fields.array(tag::PROOF)?,
        };
        fields.finish()?;
        Ok(hello)
    }
}

/// `WELCOME`: the server opens a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Welcome {
    /// Session id.
    pub session_id: [u8; 16],
    /// 32-byte server nonce.
    pub server_nonce: [u8; 32],
    /// Absolute session deadline.
    pub session_expires_at_ms: u64,
    /// Server caps.
    pub limits: Limits,
    /// Keyed proof over the hello nonce.
    pub proof: [u8; 32],
}

impl Message for Welcome {
    const KIND: Kind = Kind::Welcome;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        let mut writer = FieldWriter::new();
        writer.array(tag::SESSION_ID, &self.session_id)?;
        writer.array(tag::SERVER_NONCE, &self.server_nonce)?;
        writer.u64(tag::SESSION_EXPIRES_AT_MS, self.session_expires_at_ms)?;
        self.limits.encode_into(&mut writer, tag::LIMITS)?;
        writer.array(tag::PROOF, &self.proof)?;
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let session_id = fields.array(tag::SESSION_ID)?;
        let server_nonce = fields.array(tag::SERVER_NONCE)?;
        let session_expires_at_ms = fields.u64(tag::SESSION_EXPIRES_AT_MS)?;
        let limits = Limits::decode_from(fields.nested(tag::LIMITS)?)?;
        let proof = fields.array(tag::PROOF)?;
        fields.finish()?;
        Ok(Self {
            session_id,
            server_nonce,
            session_expires_at_ms,
            limits,
            proof,
        })
    }
}

/// `CHECKOUT`: read a directory manifest and optional bodies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkout {
    /// Namespace label.
    pub namespace: String,
    /// Canonical directory path.
    pub dir_path: String,
    /// `0` manifest only, `1` manifest plus bodies.
    pub bodies: u8,
    /// Return 304 when the current version equals this.
    pub if_dir_version: Option<[u8; 32]>,
    /// Return 304 when the global sequence equals this.
    pub if_snapshot_seq: Option<u64>,
}

impl Checkout {
    /// Check the request invariants.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Inconsistent`] or a path/namespace error.
    pub fn validate(&self) -> Result<(), ProtoError> {
        check_namespace(&self.namespace)?;
        check_path(&self.dir_path)?;
        if self.bodies > 1 {
            return Err(ProtoError::ValueOutOfRange {
                tag: tag::BODIES,
                value: u64::from(self.bodies),
                max: 1,
            });
        }
        Ok(())
    }
}

impl Message for Checkout {
    const KIND: Kind = Kind::Checkout;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        self.validate()?;
        let mut writer = FieldWriter::new();
        writer.string(tag::NAMESPACE, &self.namespace)?;
        writer.string(tag::DIR_PATH, &self.dir_path)?;
        writer.u8(tag::BODIES, self.bodies)?;
        if let Some(version) = self.if_dir_version {
            writer.array(tag::IF_DIR_VERSION, &version)?;
        }
        if let Some(seq) = self.if_snapshot_seq {
            writer.u64(tag::IF_SNAPSHOT_SEQ, seq)?;
        }
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let checkout = Self {
            namespace: fields
                .string(tag::NAMESPACE, super::types::MAX_NAMESPACE)?
                .to_owned(),
            dir_path: fields.string(tag::DIR_PATH, MAX_PATH)?.to_owned(),
            bodies: fields.u8(tag::BODIES)?,
            if_dir_version: fields.opt_array::<32>(tag::IF_DIR_VERSION)?,
            if_snapshot_seq: fields.opt_u64(tag::IF_SNAPSHOT_SEQ)?,
        };
        fields.finish()?;
        checkout.validate()?;
        Ok(checkout)
    }
}

/// `SNAPSHOT`: one consistent directory view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// Global `mm_seq`.
    pub snapshot_seq: u64,
    /// Database epoch.
    pub epoch: u64,
    /// Per-directory `dir_seq`.
    pub base_seq: u64,
    /// Directory inode.
    pub dir_ino: [u8; 16],
    /// Canonical directory path.
    pub dir_path: String,
    /// Directory version.
    pub dir_version: [u8; 32],
    /// Directory attributes.
    pub dir_attrs: DirAttrs,
    /// Direct entries.
    pub entries: Vec<Entry>,
}

impl Snapshot {
    /// Check the snapshot invariants.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Inconsistent`], duplicate names or entry errors.
    pub fn validate(&self) -> Result<(), ProtoError> {
        check_path(&self.dir_path)?;
        let limits = Limits::new();
        if self.entries.len() > limits.max_entries as usize {
            return Err(ProtoError::TooManyRecords {
                tag: tag::ENTRIES,
                count: self.entries.len() as u32,
                cap: limits.max_entries,
            });
        }
        let mut names = std::collections::BTreeSet::new();
        for entry in &self.entries {
            entry.validate_snapshot()?;
            if !names.insert(entry.name.as_str()) {
                return Err(ProtoError::Inconsistent("duplicate snapshot name"));
            }
        }
        Ok(())
    }
}

impl Message for Snapshot {
    const KIND: Kind = Kind::Snapshot;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        self.validate()?;
        let mut writer = FieldWriter::new();
        writer.u64(tag::SNAPSHOT_SEQ, self.snapshot_seq)?;
        writer.u64(tag::EPOCH, self.epoch)?;
        writer.u64(tag::BASE_SEQ, self.base_seq)?;
        writer.array(tag::DIR_INO, &self.dir_ino)?;
        writer.string(tag::DIR_PATH, &self.dir_path)?;
        writer.array(tag::DIR_VERSION, &self.dir_version)?;
        self.dir_attrs.encode_into(&mut writer, tag::DIR_ATTRS)?;
        encode_entry_list(
            &mut writer,
            tag::ENTRIES,
            Limits::new().max_entries,
            &self.entries,
        )?;
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let limits = Limits::new();
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let snapshot_seq = fields.u64(tag::SNAPSHOT_SEQ)?;
        let epoch = fields.u64(tag::EPOCH)?;
        let base_seq = fields.u64(tag::BASE_SEQ)?;
        let dir_ino = fields.array(tag::DIR_INO)?;
        let dir_path = fields.string(tag::DIR_PATH, MAX_PATH)?.to_owned();
        let dir_version = fields.array(tag::DIR_VERSION)?;
        let dir_attrs = DirAttrs::decode_from(fields.nested(tag::DIR_ATTRS)?)?;
        let records = fields.list(tag::ENTRIES, limits.max_entries)?;
        fields.finish()?;
        let entries = decode_entry_list(&records, limits.max_entries)?;
        let snapshot = Self {
            snapshot_seq,
            epoch,
            base_seq,
            dir_ino,
            dir_path,
            dir_version,
            dir_attrs,
            entries,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }
}

/// `FILE_READ`: read one byte range of one file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRead {
    /// Namespace label.
    pub namespace: String,
    /// Canonical directory path.
    pub dir_path: String,
    /// File name.
    pub name: String,
    /// Expected inode.
    pub ino: [u8; 16],
    /// Expected 64 KiB Merkle root.
    pub file_root: [u8; 32],
    /// Range start.
    pub range_offset: u64,
    /// Range length.
    pub range_len: u32,
}

impl FileRead {
    /// Check the request invariants.
    ///
    /// # Errors
    ///
    /// Path/name errors or a range above the cap.
    pub fn validate(&self) -> Result<(), ProtoError> {
        check_namespace(&self.namespace)?;
        check_path(&self.dir_path)?;
        check_name(&self.name)?;
        let max = Limits::new().max_range_len;
        if self.range_len > max {
            return Err(ProtoError::ValueOutOfRange {
                tag: tag::RANGE_LEN,
                value: u64::from(self.range_len),
                max: u64::from(max),
            });
        }
        self.range_offset
            .checked_add(u64::from(self.range_len))
            .ok_or(ProtoError::Inconsistent("range overflows"))?;
        Ok(())
    }
}

impl Message for FileRead {
    const KIND: Kind = Kind::FileRead;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        self.validate()?;
        let mut writer = FieldWriter::new();
        writer.string(tag::NAMESPACE, &self.namespace)?;
        writer.string(tag::DIR_PATH, &self.dir_path)?;
        writer.string(tag::NAME, &self.name)?;
        writer.array(tag::INO, &self.ino)?;
        writer.array(tag::FILE_ROOT, &self.file_root)?;
        writer.u64(tag::RANGE_OFFSET, self.range_offset)?;
        writer.u32(tag::RANGE_LEN, self.range_len)?;
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let read = Self {
            namespace: fields
                .string(tag::NAMESPACE, super::types::MAX_NAMESPACE)?
                .to_owned(),
            dir_path: fields.string(tag::DIR_PATH, MAX_PATH)?.to_owned(),
            name: fields.string(tag::NAME, MAX_NAME)?.to_owned(),
            ino: fields.array(tag::INO)?,
            file_root: fields.array(tag::FILE_ROOT)?,
            range_offset: fields.u64(tag::RANGE_OFFSET)?,
            range_len: fields.u32(tag::RANGE_LEN)?,
        };
        fields.finish()?;
        read.validate()?;
        Ok(read)
    }
}

/// `FILE_DATA`: the requested byte range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileData {
    /// Range start.
    pub range_offset: u64,
    /// Range length.
    pub range_len: u32,
    /// BLAKE3 of the range bytes.
    pub range_hash: [u8; 32],
}

impl FileData {
    /// Check the meta against the payload length.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Inconsistent`] when the declared range and payload differ.
    pub fn check_payload(&self, payload_len: u64) -> Result<(), ProtoError> {
        if u64::from(self.range_len) != payload_len {
            return Err(ProtoError::Inconsistent(
                "range length differs from payload",
            ));
        }
        Ok(())
    }
}

impl Message for FileData {
    const KIND: Kind = Kind::FileData;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        let max = Limits::new().max_range_len;
        if self.range_len > max {
            return Err(ProtoError::ValueOutOfRange {
                tag: tag::RANGE_LEN,
                value: u64::from(self.range_len),
                max: u64::from(max),
            });
        }
        let mut writer = FieldWriter::new();
        writer.u64(tag::RANGE_OFFSET, self.range_offset)?;
        writer.u32(tag::RANGE_LEN, self.range_len)?;
        writer.array(tag::RANGE_HASH, &self.range_hash)?;
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let data = Self {
            range_offset: fields.u64(tag::RANGE_OFFSET)?,
            range_len: fields.u32(tag::RANGE_LEN)?,
            range_hash: fields.array(tag::RANGE_HASH)?,
        };
        fields.finish()?;
        let max = Limits::new().max_range_len;
        if data.range_len > max {
            return Err(ProtoError::ValueOutOfRange {
                tag: tag::RANGE_LEN,
                value: u64::from(data.range_len),
                max: u64::from(max),
            });
        }
        Ok(data)
    }
}

/// `SIGNATURES_REQ`: ask for the base block signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureRequest {
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
    /// Directory version the client checked out.
    pub dir_version: [u8; 32],
    /// Lock id.
    pub lock_id: [u8; 16],
    /// Batch id.
    pub batch_id: [u8; 16],
    /// Files the client wants signatures for.
    pub files: Vec<SignatureFile>,
}

impl SignatureRequest {
    /// Check the request invariants.
    ///
    /// # Errors
    ///
    /// Path errors, duplicate names or too many files.
    pub fn validate(&self) -> Result<(), ProtoError> {
        check_namespace(&self.namespace)?;
        check_path(&self.dir_path)?;
        let max = Limits::new().max_entries;
        if self.files.len() > max as usize {
            return Err(ProtoError::TooManyRecords {
                tag: tag::FILES,
                count: self.files.len() as u32,
                cap: max,
            });
        }
        let mut names = std::collections::BTreeSet::new();
        for file in &self.files {
            check_name(&file.name)?;
            if file.size > Limits::new().max_file_size {
                return Err(ProtoError::ValueOutOfRange {
                    tag: tag::SIZE,
                    value: file.size,
                    max: Limits::new().max_file_size,
                });
            }
            if !names.insert(file.name.as_str()) {
                return Err(ProtoError::Inconsistent("duplicate signature name"));
            }
        }
        Ok(())
    }
}

impl Message for SignatureRequest {
    const KIND: Kind = Kind::SignaturesReq;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        self.validate()?;
        let records = self
            .files
            .iter()
            .map(SignatureFile::encode_record)
            .collect::<Result<Vec<_>, _>>()?;
        let mut writer = FieldWriter::new();
        writer.string(tag::NAMESPACE, &self.namespace)?;
        writer.string(tag::DIR_PATH, &self.dir_path)?;
        writer.array(tag::DIR_INO, &self.dir_ino)?;
        writer.u64(tag::EPOCH, self.epoch)?;
        writer.u64(tag::BASE_SEQ, self.base_seq)?;
        writer.array(tag::DIR_VERSION, &self.dir_version)?;
        writer.array(tag::LOCK_ID, &self.lock_id)?;
        writer.array(tag::BATCH_ID, &self.batch_id)?;
        writer.list(tag::FILES, Limits::new().max_entries, &records)?;
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
        let lock_id = fields.array(tag::LOCK_ID)?;
        let batch_id = fields.array(tag::BATCH_ID)?;
        let records = fields.list(tag::FILES, limits.max_entries)?;
        fields.finish()?;
        let files = records
            .iter()
            .map(|record| SignatureFile::decode_record(record))
            .collect::<Result<Vec<_>, _>>()?;
        let request = Self {
            namespace,
            dir_path,
            dir_ino,
            epoch,
            base_seq,
            dir_version,
            lock_id,
            batch_id,
            files,
        };
        request.validate()?;
        Ok(request)
    }
}

/// `SIGNATURES`: per-file block signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signatures {
    /// Database epoch.
    pub epoch: u64,
    /// Per-directory `dir_seq`.
    pub base_seq: u64,
    /// Directory version the signatures belong to.
    pub dir_version: [u8; 32],
    /// Per-file signatures.
    pub files: Vec<FileSignature>,
}

impl Signatures {
    /// Check the response invariants.
    ///
    /// # Errors
    ///
    /// Duplicate names, too many files or per-file errors.
    pub fn validate(&self) -> Result<(), ProtoError> {
        let max = Limits::new().max_entries;
        if self.files.len() > max as usize {
            return Err(ProtoError::TooManyRecords {
                tag: tag::FILES,
                count: self.files.len() as u32,
                cap: max,
            });
        }
        let mut names = std::collections::BTreeSet::new();
        for file in &self.files {
            file.validate()?;
            if !names.insert(file.name.as_str()) {
                return Err(ProtoError::Inconsistent("duplicate signature name"));
            }
        }
        Ok(())
    }
}

impl Message for Signatures {
    const KIND: Kind = Kind::Signatures;

    fn encode_meta(&self) -> Result<Vec<u8>, ProtoError> {
        self.validate()?;
        let records = self
            .files
            .iter()
            .map(FileSignature::encode_record)
            .collect::<Result<Vec<_>, _>>()?;
        let mut writer = FieldWriter::new();
        writer.u64(tag::EPOCH, self.epoch)?;
        writer.u64(tag::BASE_SEQ, self.base_seq)?;
        writer.array(tag::DIR_VERSION, &self.dir_version)?;
        writer.list(tag::FILES, Limits::new().max_entries, &records)?;
        Ok(writer.into_bytes())
    }

    fn decode_meta(meta: &[u8]) -> Result<Self, ProtoError> {
        let limits = Limits::new();
        let mut fields = Fields::parse(meta, super::field::MAX_FIELDS)?;
        let epoch = fields.u64(tag::EPOCH)?;
        let base_seq = fields.u64(tag::BASE_SEQ)?;
        let dir_version = fields.array(tag::DIR_VERSION)?;
        let records = fields.list(tag::FILES, limits.max_entries)?;
        fields.finish()?;
        let files = records
            .iter()
            .map(|record| FileSignature::decode_record(record))
            .collect::<Result<Vec<_>, _>>()?;
        let signatures = Self {
            epoch,
            base_seq,
            dir_version,
            files,
        };
        signatures.validate()?;
        Ok(signatures)
    }
}

/// Helper for tests and callers: the header width used by every frame.
pub const FRAME_HEADER_LEN: usize = HEADER_LEN;

// Keep the unused-import checker honest: these types are part of the public
// surface even when a given build only touches a subset of messages.
const _: () = {
    let _ = std::mem::size_of::<BlockSignature>();
    let _ = MAX_DETAIL;
};
