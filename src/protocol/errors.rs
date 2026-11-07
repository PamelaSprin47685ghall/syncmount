//! Protocol-layer errors and wire reason codes.
//!
//! Two families live here, and the split matters:
//!
//! * [`ProtocolError`] is a **local** error. It never travels on the wire by
//!   itself. Only errors attributable to the peer map to a [`TrnReason`].
//! * [`TrnReason`], [`KickReason`] and [`SyncEndReason`] are **wire** values
//!   carried inside `ERROR`, `KICK` and `SYNC_END` bodies.
//!
//! `ProtocolError` covers the frame/codec layer only. The crypto, identity,
//! message and fragment layers each own their error type and wrap it at their
//! own boundary; putting `CryptoError`/`WcpError` here would make the base
//! module depend on its consumers and invert the dependency graph in 44 §1.

use std::fmt;

use crate::protocol::version::VersionError;

/// A frame or codec failure detected locally.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProtocolError {
    /// The underlying byte stream failed. Not attributable to the peer.
    Io(std::io::Error),
    /// The stream ended in the middle of a frame.
    Truncated {
        /// Bytes required to finish the frame.
        need: usize,
        /// Bytes actually available.
        got: usize,
    },
    /// First header byte was not [`crate::protocol::frame::MAGIC`].
    BadMagic(u8),
    /// Frame format version is outside the supported set.
    UnsupportedFrameVer(u8),
    /// Message type is not one of the 14 defined types.
    UnknownType(u8),
    /// Flags contradict each other or the message type.
    FlagsConflict(u16),
    /// Reserved flag bits (bit6/bit7) were set.
    ReservedFlags(u16),
    /// `len` is outside `[prefix_len + min_body, cap]`.
    BadLen {
        /// Declared `len` field.
        len: u32,
        /// Prefix width implied by the flags.
        prefix: u8,
        /// Effective cap (ingress limit or protocol ceiling).
        cap: u32,
    },
    /// `len` cannot hold the prefix plus the smallest legal body.
    BodyTooShort {
        /// Declared `len` field.
        len: u32,
        /// Prefix width implied by the flags.
        prefix: u8,
        /// Smallest body the encoding allows.
        min_body: u32,
    },
    /// A prefix was present where the type forbids it, or absent where it is
    /// required.
    UnexpectedPrefix,
    /// Route-prefix chunk bookkeeping is inconsistent.
    BadChunkBounds {
        /// Declared chunk index.
        chunk_index: u32,
        /// Declared total chunk count.
        total_chunks: u32,
    },
    /// A control-prefix reserved field was not zero.
    NonZeroReserved(u16),
    /// [`crate::protocol::frame::Limits`] cannot describe any legal frame.
    InvalidLimits {
        /// Configured ingress limit.
        ingress_frame: u32,
        /// Protocol ceiling.
        cap: u32,
    },
    /// The incremental decoder buffer would exceed its bound.
    BufferOverflow {
        /// Bytes that would be buffered.
        buffered: usize,
        /// Allowed bound.
        cap: usize,
    },
    /// Version negotiation failed.
    Version(VersionError),
}

impl ProtocolError {
    /// Map an error to the wire reason the peer may be blamed for.
    ///
    /// Returns `None` for transport failures and local bugs: an I/O error is
    /// a broken link, a truncation is an aborted stream, and invalid local
    /// limits are our own configuration mistake. Sending `TRN_BAD_FRAME` for
    /// any of those would blame the wrong party (44 §7.5).
    pub fn to_wire(&self) -> Option<TrnReason> {
        match self {
            Self::BadMagic(_)
            | Self::BadLen { .. }
            | Self::BodyTooShort { .. }
            | Self::FlagsConflict(_)
            | Self::ReservedFlags(_)
            | Self::UnknownType(_)
            | Self::UnexpectedPrefix
            | Self::BadChunkBounds { .. }
            | Self::NonZeroReserved(_)
            | Self::BufferOverflow { .. } => Some(TrnReason::BadFrame),
            Self::UnsupportedFrameVer(_) | Self::Version(_) => Some(TrnReason::Version),
            Self::Io(_) | Self::Truncated { .. } | Self::InvalidLimits { .. } => None,
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "i/o error: {e}"),
            Self::Truncated { need, got } => {
                write!(f, "truncated frame: need {need} bytes, got {got}")
            }
            Self::BadMagic(m) => write!(f, "bad magic 0x{m:02x}, expected 0x53"),
            Self::UnsupportedFrameVer(v) => write!(f, "unsupported frame version {v}"),
            Self::UnknownType(t) => write!(f, "unknown message type 0x{t:02x}"),
            Self::FlagsConflict(bits) => write!(f, "conflicting frame flags 0x{bits:04x}"),
            Self::ReservedFlags(bits) => {
                write!(f, "reserved frame flag bits set: 0x{bits:04x}")
            }
            Self::BadLen { len, prefix, cap } => write!(
                f,
                "bad frame length {len} (prefix {prefix} bytes, cap {cap})"
            ),
            Self::BodyTooShort {
                len,
                prefix,
                min_body,
            } => write!(
                f,
                "frame length {len} cannot hold prefix {prefix} plus minimum body {min_body}"
            ),
            Self::UnexpectedPrefix => write!(f, "prefix does not match message type"),
            Self::BadChunkBounds {
                chunk_index,
                total_chunks,
            } => write!(
                f,
                "bad chunk bounds: chunk_index {chunk_index}, total_chunks {total_chunks}"
            ),
            Self::NonZeroReserved(value) => {
                write!(
                    f,
                    "control prefix reserved field is 0x{value:04x}, must be 0"
                )
            }
            Self::InvalidLimits { ingress_frame, cap } => write!(
                f,
                "invalid ingress_frame limit {ingress_frame} (protocol ceiling {cap})"
            ),
            Self::BufferOverflow { buffered, cap } => {
                write!(f, "decoder buffer overflow: {buffered} bytes > {cap} bytes")
            }
            Self::Version(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Version(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ProtocolError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<VersionError> for ProtocolError {
    fn from(value: VersionError) -> Self {
        Self::Version(value)
    }
}

/// `F_TRN_REASON` values carried by an `ERROR` frame (44 §7.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u16)]
pub enum TrnReason {
    /// Never sent; reserved as the "no error" sentinel.
    Ok = 0,
    /// Frame or protocol version mismatch.
    Version = 1,
    /// Join proof or PSK check failed.
    Auth = 2,
    /// Malformed frame; retry a bounded number of times.
    BadFrame = 3,
    /// Route or sync session is unknown.
    SessionUnknown = 4,
    /// Session table is full.
    SessionFull = 5,
    /// No peer is available for the requested session.
    NoPeer = 6,
    /// Sender must stop until a `FLOW` frame arrives.
    Backpressure = 7,
    /// Downlink queue overflow; the connection is about to be kicked.
    QueueOverflow = 8,
    /// Server is saturated; back off and reconnect.
    ServerBusy = 9,
    /// The peer violated a protocol rule.
    Protocol = 10,
    /// `epoch_seen` does not match the server epoch.
    EpochMismatch = 11,
    /// The client applied too slowly and was kicked.
    SlowClient = 12,
    /// Internal server failure.
    Internal = 13,
}

impl TrnReason {
    /// Decode a wire value. Unknown values are rejected, not coerced.
    pub const fn from_u16(raw: u16) -> Option<Self> {
        Some(match raw {
            0 => Self::Ok,
            1 => Self::Version,
            2 => Self::Auth,
            3 => Self::BadFrame,
            4 => Self::SessionUnknown,
            5 => Self::SessionFull,
            6 => Self::NoPeer,
            7 => Self::Backpressure,
            8 => Self::QueueOverflow,
            9 => Self::ServerBusy,
            10 => Self::Protocol,
            11 => Self::EpochMismatch,
            12 => Self::SlowClient,
            13 => Self::Internal,
            _ => return None,
        })
    }

    /// Wire value.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Whether the client may retry after this reason.
    pub const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::BadFrame
                | Self::SessionFull
                | Self::NoPeer
                | Self::Backpressure
                | Self::ServerBusy
                | Self::Internal
        )
    }

    /// Stable name for logs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ok => "TRN_OK",
            Self::Version => "TRN_VERSION",
            Self::Auth => "TRN_AUTH",
            Self::BadFrame => "TRN_BAD_FRAME",
            Self::SessionUnknown => "TRN_SESSION_UNKNOWN",
            Self::SessionFull => "TRN_SESSION_FULL",
            Self::NoPeer => "TRN_NO_PEER",
            Self::Backpressure => "TRN_BACKPRESSURE",
            Self::QueueOverflow => "TRN_QUEUE_OVERFLOW",
            Self::ServerBusy => "TRN_SERVER_BUSY",
            Self::Protocol => "TRN_PROTOCOL",
            Self::EpochMismatch => "TRN_EPOCH_MISMATCH",
            Self::SlowClient => "TRN_SLOW_CLIENT",
            Self::Internal => "TRN_INTERNAL",
        }
    }
}

/// `F_KICK_REASON` values carried by a `KICK` frame (44 §7.2).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u16)]
pub enum KickReason {
    /// Credentials or join proof failed.
    AuthFail = 1,
    /// Major protocol version mismatch.
    Version = 2,
    /// No `PING` within the heartbeat window.
    HeartbeatTimeout = 3,
    /// `applied_seq` stopped advancing past the dynamic threshold.
    Stalled = 4,
    /// `applied_seq` moved backwards.
    Regression = 5,
    /// `applied_seq` exceeded `current_seq`.
    Overclaim = 6,
    /// The same `client_id` opened a second connection.
    DuplicateClient = 7,
    /// Downlink backlog exceeded the queue budget.
    QueueOverflow = 8,
    /// `epoch_seen` changed mid-connection.
    EpochMismatch = 9,
    /// The server is shutting down.
    ServerShutdown = 10,
}

impl KickReason {
    /// Decode a wire value.
    pub const fn from_u16(raw: u16) -> Option<Self> {
        Some(match raw {
            1 => Self::AuthFail,
            2 => Self::Version,
            3 => Self::HeartbeatTimeout,
            4 => Self::Stalled,
            5 => Self::Regression,
            6 => Self::Overclaim,
            7 => Self::DuplicateClient,
            8 => Self::QueueOverflow,
            9 => Self::EpochMismatch,
            10 => Self::ServerShutdown,
            _ => return None,
        })
    }

    /// Wire value.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Stable name for logs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::AuthFail => "AUTH_FAIL",
            Self::Version => "VERSION",
            Self::HeartbeatTimeout => "HEARTBEAT_TIMEOUT",
            Self::Stalled => "STALLED",
            Self::Regression => "REGRESSION",
            Self::Overclaim => "OVERCLAIM",
            Self::DuplicateClient => "DUPLICATE_CLIENT",
            Self::QueueOverflow => "QUEUE_OVERFLOW",
            Self::EpochMismatch => "EPOCH_MISMATCH",
            Self::ServerShutdown => "SERVER_SHUTDOWN",
        }
    }
}

/// `F_SYNC_REASON` values carried by a `SYNC_END` frame (44 §7.3).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum SyncEndReason {
    /// The sync session finished normally.
    Done = 1,
    /// The initiator cancelled.
    Cancel = 2,
    /// The session expired.
    Timeout = 3,
    /// The source side failed.
    Failed = 4,
    /// No peer was available.
    NoPeer = 5,
    /// A block was missing and the retry budget ran out.
    BlockMiss = 6,
}

impl SyncEndReason {
    /// Decode a wire value.
    pub const fn from_u8(raw: u8) -> Option<Self> {
        Some(match raw {
            1 => Self::Done,
            2 => Self::Cancel,
            3 => Self::Timeout,
            4 => Self::Failed,
            5 => Self::NoPeer,
            6 => Self::BlockMiss,
            _ => return None,
        })
    }

    /// Wire value.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Stable name for logs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Done => "DONE",
            Self::Cancel => "CANCEL",
            Self::Timeout => "TIMEOUT",
            Self::Failed => "FAILED",
            Self::NoPeer => "NO_PEER",
            Self::BlockMiss => "BLOCK_MISS",
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn trn_reason_roundtrips_and_rejects_unknown() {
        for raw in 0u16..=13 {
            let reason = TrnReason::from_u16(raw).expect("defined reason");
            assert_eq!(reason.as_u16(), raw);
            assert!(!reason.name().is_empty());
        }
        assert_eq!(TrnReason::from_u16(14), None);
        assert_eq!(TrnReason::from_u16(u16::MAX), None);
    }

    #[test]
    fn kick_reason_roundtrips_and_rejects_unknown() {
        for raw in 1u16..=10 {
            let reason = KickReason::from_u16(raw).expect("defined reason");
            assert_eq!(reason.as_u16(), raw);
        }
        assert_eq!(KickReason::from_u16(0), None);
        assert_eq!(KickReason::from_u16(11), None);
    }

    #[test]
    fn sync_end_reason_roundtrips_and_rejects_unknown() {
        for raw in 1u8..=6 {
            let reason = SyncEndReason::from_u8(raw).expect("defined reason");
            assert_eq!(reason.as_u8(), raw);
        }
        assert_eq!(SyncEndReason::from_u8(0), None);
        assert_eq!(SyncEndReason::from_u8(7), None);
    }

    #[test]
    fn io_and_truncation_never_blame_the_peer() {
        let io = ProtocolError::Io(std::io::Error::other("boom"));
        assert_eq!(io.to_wire(), None);
        let truncated = ProtocolError::Truncated { need: 21, got: 4 };
        assert_eq!(truncated.to_wire(), None);
    }

    #[test]
    fn malformed_frames_map_to_bad_frame() {
        assert_eq!(
            ProtocolError::BadMagic(0).to_wire(),
            Some(TrnReason::BadFrame)
        );
        assert_eq!(
            ProtocolError::UnknownType(0x99).to_wire(),
            Some(TrnReason::BadFrame)
        );
        assert_eq!(
            ProtocolError::UnsupportedFrameVer(9).to_wire(),
            Some(TrnReason::Version)
        );
    }
}
