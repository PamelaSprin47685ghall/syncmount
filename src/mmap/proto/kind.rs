//! SMM1 message kinds.
//!
//! The kind table is closed. A decoder rejects any value not listed here, so a
//! future extension needs a new protocol version, not a silent skip.

use super::error::ProtoError;

/// A SMM1 message kind (`header.kind`).
///
/// Requests and responses share one numbering space. `Error` is terminal for
/// every request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Kind {
    /// Client hello, carries the proof over the hello key.
    Hello = 0x01,
    /// Server welcome, carries the session and limits.
    Welcome = 0x02,
    /// Read a directory manifest and optional bodies.
    Checkout = 0x10,
    /// Directory manifest and optional file bodies.
    Snapshot = 0x11,
    /// Ask for rsync signatures of the current base.
    SignaturesReq = 0x12,
    /// Per-file block signatures.
    Signatures = 0x13,
    /// Open an upload batch.
    UploadBegin = 0x14,
    /// Server plan for an upload batch.
    UploadPlan = 0x15,
    /// Commit an upload batch, followed by an instruction stream.
    UploadCommit = 0x16,
    /// Committed batch result.
    UploadResult = 0x17,
    /// Abort an upload batch.
    UploadAbort = 0x18,
    /// Abort acknowledgement.
    Aborted = 0x19,
    /// Acquire the per-directory upload lock.
    LockAcquire = 0x1A,
    /// Lock grant with the base it protects.
    LockGranted = 0x1B,
    /// Extend a lock lease.
    LockRenew = 0x1C,
    /// Extended lease.
    LockRenewed = 0x1D,
    /// Release a lock.
    LockRelease = 0x1E,
    /// Release acknowledgement.
    LockReleased = 0x1F,
    /// Ask for a batch state.
    BatchStatus = 0x20,
    /// Batch state answer.
    BatchState = 0x21,
    /// Read a byte range of one file.
    FileRead = 0x22,
    /// Byte range answer.
    FileData = 0x23,
    /// Ask for the current directory version.
    DirVersionReq = 0x24,
    /// Current directory version.
    DirVersion = 0x25,
    /// Terminal error for any request.
    Error = 0x7F,
}

impl Kind {
    /// Decode one kind byte.
    ///
    /// # Errors
    ///
    /// [`ProtoError::UnknownKind`] for any value outside the closed table.
    pub const fn from_u8(raw: u8) -> Result<Self, ProtoError> {
        match raw {
            0x01 => Ok(Self::Hello),
            0x02 => Ok(Self::Welcome),
            0x10 => Ok(Self::Checkout),
            0x11 => Ok(Self::Snapshot),
            0x12 => Ok(Self::SignaturesReq),
            0x13 => Ok(Self::Signatures),
            0x14 => Ok(Self::UploadBegin),
            0x15 => Ok(Self::UploadPlan),
            0x16 => Ok(Self::UploadCommit),
            0x17 => Ok(Self::UploadResult),
            0x18 => Ok(Self::UploadAbort),
            0x19 => Ok(Self::Aborted),
            0x1A => Ok(Self::LockAcquire),
            0x1B => Ok(Self::LockGranted),
            0x1C => Ok(Self::LockRenew),
            0x1D => Ok(Self::LockRenewed),
            0x1E => Ok(Self::LockRelease),
            0x1F => Ok(Self::LockReleased),
            0x20 => Ok(Self::BatchStatus),
            0x21 => Ok(Self::BatchState),
            0x22 => Ok(Self::FileRead),
            0x23 => Ok(Self::FileData),
            0x24 => Ok(Self::DirVersionReq),
            0x25 => Ok(Self::DirVersion),
            0x7F => Ok(Self::Error),
            other => Err(ProtoError::UnknownKind(other)),
        }
    }

    /// The wire byte.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Stable name for logs and tests.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Hello => "HELLO",
            Self::Welcome => "WELCOME",
            Self::Checkout => "CHECKOUT",
            Self::Snapshot => "SNAPSHOT",
            Self::SignaturesReq => "SIGNATURES_REQ",
            Self::Signatures => "SIGNATURES",
            Self::UploadBegin => "UPLOAD_BEGIN",
            Self::UploadPlan => "UPLOAD_PLAN",
            Self::UploadCommit => "UPLOAD_COMMIT",
            Self::UploadResult => "UPLOAD_RESULT",
            Self::UploadAbort => "UPLOAD_ABORT",
            Self::Aborted => "ABORTED",
            Self::LockAcquire => "LOCK_ACQUIRE",
            Self::LockGranted => "LOCK_GRANTED",
            Self::LockRenew => "LOCK_RENEW",
            Self::LockRenewed => "LOCK_RENEWED",
            Self::LockRelease => "LOCK_RELEASE",
            Self::LockReleased => "LOCK_RELEASED",
            Self::BatchStatus => "BATCH_STATUS",
            Self::BatchState => "BATCH_STATE",
            Self::FileRead => "FILE_READ",
            Self::FileData => "FILE_DATA",
            Self::DirVersionReq => "DIR_VERSION_REQ",
            Self::DirVersion => "DIR_VERSION",
            Self::Error => "ERROR",
        }
    }

    /// Whether the kind is the terminal error frame.
    pub const fn is_error(self) -> bool {
        matches!(self, Self::Error)
    }
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn every_kind_round_trips() {
        let kinds = [
            Kind::Hello,
            Kind::Welcome,
            Kind::Checkout,
            Kind::Snapshot,
            Kind::SignaturesReq,
            Kind::Signatures,
            Kind::UploadBegin,
            Kind::UploadPlan,
            Kind::UploadCommit,
            Kind::UploadResult,
            Kind::UploadAbort,
            Kind::Aborted,
            Kind::LockAcquire,
            Kind::LockGranted,
            Kind::LockRenew,
            Kind::LockRenewed,
            Kind::LockRelease,
            Kind::LockReleased,
            Kind::BatchStatus,
            Kind::BatchState,
            Kind::FileRead,
            Kind::FileData,
            Kind::DirVersionReq,
            Kind::DirVersion,
            Kind::Error,
        ];
        for kind in kinds {
            assert_eq!(Kind::from_u8(kind.as_u8()).unwrap(), kind);
            assert!(!kind.name().is_empty());
        }
    }

    #[test]
    fn unknown_kind_is_rejected() {
        for raw in [0x00, 0x03, 0x0F, 0x26, 0x7E, 0x80, 0xFF] {
            assert!(matches!(
                Kind::from_u8(raw),
                Err(ProtoError::UnknownKind(value)) if value == raw
            ));
        }
    }
}
