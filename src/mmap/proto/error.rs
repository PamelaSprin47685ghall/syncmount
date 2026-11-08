//! Errors, wire error codes and their HTTP status mapping.
//!
//! Two layers are deliberately separate:
//!
//! * [`ProtoError`] is local. It describes why this end refused a byte string
//!   and never travels by itself.
//! * [`ErrorCode`] is the stable wire vocabulary carried in an `ERROR` body.
//!   [`ErrorCode::http_status`] is the only place that maps it to HTTP.
//!
//! A local decode failure has a *default* error code so a server can answer
//! without inventing one, but the caller may replace it with a more precise
//! code (for example `TOO_MANY_ENTRIES` instead of `TOO_LARGE`).

use std::fmt;

use thiserror::Error;

/// The stable wire error vocabulary (`error_code`, tag 0x28).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ErrorCode {
    /// Envelope or field encoding is malformed.
    BadRequest = 1,
    /// A path is not canonical or exceeds the path limit.
    PathInvalid = 2,
    /// Hello proof or request MAC failed.
    AuthFailed = 3,
    /// The session is idle-expired or unknown.
    SessionExpired = 4,
    /// The directory does not exist.
    DirNotFound = 5,
    /// The target exists but is not a directory.
    NotADirectory = 6,
    /// The batch does not exist or was collected.
    BatchNotFound = 7,
    /// `(epoch, base_seq, dir_version)` does not match the server.
    BaseChanged = 8,
    /// Signatures were computed for a different base.
    SignatureStale = 9,
    /// The manifest omits a direct entry.
    ManifestIncomplete = 10,
    /// The manifest has duplicate, illegal or contradictory entries.
    ManifestInvalid = 11,
    /// Rebuilt file BLAKE3 does not match the manifest.
    HashMismatch = 12,
    /// Rebuilt file length does not match the manifest.
    SizeMismatch = 13,
    /// The same `batch_id` carries a different manifest.
    BatchConflict = 14,
    /// The batch is already committed.
    BatchCommitted = 15,
    /// The batch is already aborted.
    BatchAborted = 16,
    /// A client-chosen inode is already in use.
    InoConflict = 17,
    /// A name already exists or a rename target conflicts.
    NameConflict = 18,
    /// `DIR_REMOVE` targets a non-empty directory.
    DirNotEmpty = 19,
    /// The file changed between checkout and `FILE_READ`.
    FileChanged = 20,
    /// The instruction stream does not match the manifest.
    InstructionMismatch = 21,
    /// A manifest, file, range or batch exceeds its limit.
    TooLarge = 22,
    /// Too many direct entries.
    TooManyEntries = 23,
    /// Too many signature blocks.
    TooManyBlocks = 24,
    /// Another owner holds the upload lock.
    LockHeld = 25,
    /// The caller is not the lock owner, or the lock was collected.
    LockLost = 26,
    /// The lock lease expired.
    LockExpired = 27,
    /// Unexpected server failure.
    Internal = 28,
    /// The store or queue is saturated.
    Busy = 29,
    /// The store thread stopped.
    StoreGone = 30,
    /// The spool filesystem is full.
    NoSpace = 31,
}

impl ErrorCode {
    /// Decode one wire value.
    ///
    /// # Errors
    ///
    /// [`ProtoError::BadEnum`] for an unknown code.
    pub const fn from_u16(raw: u16) -> Result<Self, ProtoError> {
        match raw {
            1 => Ok(Self::BadRequest),
            2 => Ok(Self::PathInvalid),
            3 => Ok(Self::AuthFailed),
            4 => Ok(Self::SessionExpired),
            5 => Ok(Self::DirNotFound),
            6 => Ok(Self::NotADirectory),
            7 => Ok(Self::BatchNotFound),
            8 => Ok(Self::BaseChanged),
            9 => Ok(Self::SignatureStale),
            10 => Ok(Self::ManifestIncomplete),
            11 => Ok(Self::ManifestInvalid),
            12 => Ok(Self::HashMismatch),
            13 => Ok(Self::SizeMismatch),
            14 => Ok(Self::BatchConflict),
            15 => Ok(Self::BatchCommitted),
            16 => Ok(Self::BatchAborted),
            17 => Ok(Self::InoConflict),
            18 => Ok(Self::NameConflict),
            19 => Ok(Self::DirNotEmpty),
            20 => Ok(Self::FileChanged),
            21 => Ok(Self::InstructionMismatch),
            22 => Ok(Self::TooLarge),
            23 => Ok(Self::TooManyEntries),
            24 => Ok(Self::TooManyBlocks),
            25 => Ok(Self::LockHeld),
            26 => Ok(Self::LockLost),
            27 => Ok(Self::LockExpired),
            28 => Ok(Self::Internal),
            29 => Ok(Self::Busy),
            30 => Ok(Self::StoreGone),
            31 => Ok(Self::NoSpace),
            other => Err(ProtoError::BadEnum {
                tag: super::tag::ERROR_CODE,
                value: other as u64,
            }),
        }
    }

    /// The wire value.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Stable SCREAMING_SNAKE name used in JSON bodies and logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "BAD_REQUEST",
            Self::PathInvalid => "PATH_INVALID",
            Self::AuthFailed => "AUTH_FAILED",
            Self::SessionExpired => "SESSION_EXPIRED",
            Self::DirNotFound => "DIR_NOT_FOUND",
            Self::NotADirectory => "NOT_A_DIRECTORY",
            Self::BatchNotFound => "BATCH_NOT_FOUND",
            Self::BaseChanged => "BASE_CHANGED",
            Self::SignatureStale => "SIGNATURE_STALE",
            Self::ManifestIncomplete => "MANIFEST_INCOMPLETE",
            Self::ManifestInvalid => "MANIFEST_INVALID",
            Self::HashMismatch => "HASH_MISMATCH",
            Self::SizeMismatch => "SIZE_MISMATCH",
            Self::BatchConflict => "BATCH_CONFLICT",
            Self::BatchCommitted => "BATCH_COMMITTED",
            Self::BatchAborted => "BATCH_ABORTED",
            Self::InoConflict => "INO_CONFLICT",
            Self::NameConflict => "NAME_CONFLICT",
            Self::DirNotEmpty => "DIR_NOT_EMPTY",
            Self::FileChanged => "FILE_CHANGED",
            Self::InstructionMismatch => "INSTRUCTION_MISMATCH",
            Self::TooLarge => "TOO_LARGE",
            Self::TooManyEntries => "TOO_MANY_ENTRIES",
            Self::TooManyBlocks => "TOO_MANY_BLOCKS",
            Self::LockHeld => "LOCK_HELD",
            Self::LockLost => "LOCK_LOST",
            Self::LockExpired => "LOCK_EXPIRED",
            Self::Internal => "INTERNAL",
            Self::Busy => "BUSY",
            Self::StoreGone => "STORE_GONE",
            Self::NoSpace => "NO_SPACE",
        }
    }

    /// The HTTP status this code maps to.
    ///
    /// 422 is the task's format/semantic-error bucket: a body can be a
    /// well-formed SMM1 envelope and still fail manifest, hash, size or
    /// instruction semantics. 409 stays reserved for *state* conflicts.
    pub const fn http_status(self) -> u16 {
        match self {
            Self::BadRequest | Self::PathInvalid => 400,
            Self::AuthFailed | Self::SessionExpired => 401,
            Self::DirNotFound | Self::NotADirectory | Self::BatchNotFound => 404,
            Self::BaseChanged
            | Self::SignatureStale
            | Self::ManifestIncomplete
            | Self::BatchConflict
            | Self::BatchCommitted
            | Self::BatchAborted
            | Self::InoConflict
            | Self::NameConflict
            | Self::DirNotEmpty
            | Self::FileChanged => 409,
            Self::ManifestInvalid
            | Self::HashMismatch
            | Self::SizeMismatch
            | Self::InstructionMismatch => 422,
            Self::TooLarge | Self::TooManyEntries | Self::TooManyBlocks => 413,
            Self::LockHeld | Self::LockLost | Self::LockExpired => 423,
            Self::Internal => 500,
            Self::Busy | Self::StoreGone => 503,
            Self::NoSpace => 507,
        }
    }

    /// Whether the code means "try again on the next `fsync`", not now.
    pub const fn is_deferred(self) -> bool {
        matches!(
            self,
            Self::BaseChanged
                | Self::SignatureStale
                | Self::ManifestIncomplete
                | Self::LockHeld
                | Self::LockLost
                | Self::LockExpired
                | Self::Busy
        )
    }

    /// Whether the code asks the client to fall back to a full upload.
    pub const fn requests_full_retry(self) -> bool {
        matches!(self, Self::HashMismatch | Self::SizeMismatch)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A hello or request authentication failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AuthError {
    /// `timestamp_ms` is outside `now ± 60 s`.
    #[error("timestamp skew: now {now_ms} ms, peer {timestamp_ms} ms")]
    TimestampSkew {
        /// Local clock.
        now_ms: u64,
        /// Peer clock.
        timestamp_ms: u64,
    },
    /// The hello or welcome proof did not verify.
    #[error("bad proof")]
    BadProof,
    /// The client nonce is still inside the replay window.
    #[error("replayed client nonce")]
    NonceReplay,
    /// The request sequence is not strictly greater than the last seen one.
    #[error("replayed sequence {seq}, last {last_seq}")]
    SeqReplay {
        /// Offered sequence.
        seq: u64,
        /// Highest accepted sequence.
        last_seq: u64,
    },
    /// The session is past its expiry.
    #[error("session expired: now {now_ms} ms, expires {expires_at_ms} ms")]
    SessionExpired {
        /// Local clock.
        now_ms: u64,
        /// Session deadline.
        expires_at_ms: u64,
    },
    /// The request MAC did not verify.
    #[error("bad request MAC")]
    BadMac,
    /// The MAC method is not `GET` or `POST`.
    #[error("bad MAC method")]
    BadMethod,
    /// The MAC path is empty, not absolute, too long or contains NUL.
    #[error("bad MAC path")]
    BadPath,
}

impl AuthError {
    /// The wire error code for this failure.
    pub const fn code(self) -> ErrorCode {
        match self {
            Self::SessionExpired { .. } => ErrorCode::SessionExpired,
            Self::TimestampSkew { .. }
            | Self::BadProof
            | Self::NonceReplay
            | Self::SeqReplay { .. }
            | Self::BadMac => ErrorCode::AuthFailed,
            Self::BadMethod | Self::BadPath => ErrorCode::BadRequest,
        }
    }
}

/// A local SMM1 failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProtoError {
    /// The underlying stream failed.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    /// The stream ended inside a header, field or record.
    #[error("truncated: need {need} bytes, got {got}")]
    Truncated {
        /// Bytes required.
        need: usize,
        /// Bytes available.
        got: usize,
    },
    /// The first four bytes were not `SMM1`.
    #[error("bad magic {0:?}")]
    BadMagic([u8; 4]),
    /// `ver` is not 1.
    #[error("unsupported SMM version {0}")]
    UnsupportedVersion(u8),
    /// `kind` is outside the closed table.
    #[error("unknown kind {0:#04x}")]
    UnknownKind(u8),
    /// `flags` carries a bit this version does not define.
    #[error("reserved flags {0:#06x}")]
    ReservedFlags(u16),
    /// `reserved` was not zero.
    #[error("non-zero reserved word {0:#010x}")]
    NonZeroReserved(u32),
    /// `meta_len` exceeds the configured cap.
    #[error("meta too large: {len} > {cap}")]
    MetaTooLarge {
        /// Declared length.
        len: u64,
        /// Configured cap.
        cap: u64,
    },
    /// `data_len` exceeds the configured cap.
    #[error("data too large: {len} > {cap}")]
    DataTooLarge {
        /// Declared length.
        len: u64,
        /// Configured cap.
        cap: u64,
    },
    /// A field tag is not in the message's allowed set.
    #[error("unknown tag {0:#04x}")]
    UnknownTag(u8),
    /// A field tag appeared twice.
    #[error("duplicate tag {0:#04x}")]
    DuplicateTag(u8),
    /// A required field is absent.
    #[error("missing field {0:#04x}")]
    MissingField(u8),
    /// A field value has the wrong width.
    #[error("field {tag:#04x}: expected {expected}, got {got} bytes")]
    BadFieldLen {
        /// Field tag.
        tag: u8,
        /// Expected width description.
        expected: &'static str,
        /// Actual width.
        got: usize,
    },
    /// A string field is not UTF-8.
    #[error("field {tag:#04x}: invalid UTF-8")]
    BadUtf8 {
        /// Field tag.
        tag: u8,
    },
    /// A string field contains a NUL byte.
    #[error("field {tag:#04x}: NUL in string")]
    NulInString {
        /// Field tag.
        tag: u8,
    },
    /// A numeric or string value exceeds its semantic cap.
    #[error("field {tag:#04x}: value {value} exceeds {max}")]
    ValueOutOfRange {
        /// Field tag.
        tag: u8,
        /// Offered value.
        value: u64,
        /// Cap.
        max: u64,
    },
    /// An enum byte or halfword is not defined.
    #[error("field {tag:#04x}: unknown enum value {value}")]
    BadEnum {
        /// Field tag.
        tag: u8,
        /// Offered value.
        value: u64,
    },
    /// Bytes remain after the last field.
    #[error("trailing bytes: {0}")]
    TrailingBytes(usize),
    /// A field stream carries more fields than the cap.
    #[error("too many fields: {0}")]
    TooManyFields(usize),
    /// A list carries more records than the cap.
    #[error("field {tag:#04x}: too many records {count} > {cap}")]
    TooManyRecords {
        /// Field tag.
        tag: u8,
        /// Offered count.
        count: u32,
        /// Cap.
        cap: u32,
    },
    /// Field values contradict each other or the record kind.
    #[error("inconsistent message: {0}")]
    Inconsistent(&'static str),
    /// A typed decoder received a different header kind.
    #[error("wrong kind: expected {expected:#04x}, got {got:#04x}")]
    WrongKind {
        /// Kind the type requires.
        expected: u8,
        /// Kind in the header.
        got: u8,
    },
    /// Authentication failed.
    #[error("auth: {0}")]
    Auth(#[from] AuthError),
    /// The instruction stream is malformed.
    #[error("instruction stream: {0}")]
    Instruction(&'static str),
}

impl ProtoError {
    /// The default wire code for this failure.
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::Io(_) => ErrorCode::Internal,
            Self::MetaTooLarge { .. } | Self::DataTooLarge { .. } => ErrorCode::TooLarge,
            Self::TooManyRecords { tag, .. } => {
                if *tag == super::tag::BLOCKS {
                    ErrorCode::TooManyBlocks
                } else {
                    ErrorCode::TooManyEntries
                }
            }
            Self::Auth(error) => error.code(),
            Self::ValueOutOfRange { .. }
            | Self::BadEnum { .. }
            | Self::Inconsistent(_)
            | Self::Instruction(_) => ErrorCode::ManifestInvalid,
            _ => ErrorCode::BadRequest,
        }
    }
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn codes_round_trip_and_keep_their_status() {
        let codes = [
            ErrorCode::BadRequest,
            ErrorCode::PathInvalid,
            ErrorCode::AuthFailed,
            ErrorCode::SessionExpired,
            ErrorCode::DirNotFound,
            ErrorCode::NotADirectory,
            ErrorCode::BatchNotFound,
            ErrorCode::BaseChanged,
            ErrorCode::SignatureStale,
            ErrorCode::ManifestIncomplete,
            ErrorCode::ManifestInvalid,
            ErrorCode::HashMismatch,
            ErrorCode::SizeMismatch,
            ErrorCode::BatchConflict,
            ErrorCode::BatchCommitted,
            ErrorCode::BatchAborted,
            ErrorCode::InoConflict,
            ErrorCode::NameConflict,
            ErrorCode::DirNotEmpty,
            ErrorCode::FileChanged,
            ErrorCode::InstructionMismatch,
            ErrorCode::TooLarge,
            ErrorCode::TooManyEntries,
            ErrorCode::TooManyBlocks,
            ErrorCode::LockHeld,
            ErrorCode::LockLost,
            ErrorCode::LockExpired,
            ErrorCode::Internal,
            ErrorCode::Busy,
            ErrorCode::StoreGone,
            ErrorCode::NoSpace,
        ];
        for code in codes {
            assert_eq!(ErrorCode::from_u16(code.as_u16()).unwrap(), code);
            assert!(!code.as_str().is_empty());
            assert!((400..=599).contains(&code.http_status()));
        }
    }

    #[test]
    fn status_buckets_match_the_design() {
        assert_eq!(ErrorCode::AuthFailed.http_status(), 401);
        assert_eq!(ErrorCode::BaseChanged.http_status(), 409);
        assert_eq!(ErrorCode::LockHeld.http_status(), 423);
        assert_eq!(ErrorCode::TooManyEntries.http_status(), 413);
        assert_eq!(ErrorCode::ManifestInvalid.http_status(), 422);
        assert_eq!(ErrorCode::HashMismatch.http_status(), 422);
        assert_eq!(ErrorCode::InstructionMismatch.http_status(), 422);
        assert!(ErrorCode::LockHeld.is_deferred());
        assert!(!ErrorCode::ManifestInvalid.is_deferred());
        assert!(ErrorCode::HashMismatch.requests_full_retry());
    }

    #[test]
    fn unknown_code_is_rejected() {
        for raw in [0u16, 32, 0xFFFF] {
            assert!(matches!(
                ErrorCode::from_u16(raw),
                Err(ProtoError::BadEnum { .. })
            ));
        }
    }
}
