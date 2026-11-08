//! Message bodies: the WCP field codec, the 14-type message table, op classes
//! and the sealed-message decoder.
//!
//! Owner: W5 (E1). See 44 §3 and 53 W5. This module is sans-io: it turns
//! plaintext WCP bytes into structures and back, and never touches keys,
//! signatures or the network. Signature verification belongs to W4
//! (`identity`); AEAD sealing belongs to W3 (`crypto`).
//!
//! # WCP
//!
//! ```text
//! body  = field*
//! field = fid u8 | len u16 LE | value[len]
//! ```
//!
//! The first field is always `F_WCP_VER`. Encoding sorts fields by fid;
//! decoding accepts any order, rejects duplicate fids, and keeps unknown fids
//! for forward compatibility (44 §3.3, R7). [`FieldMap`] is a zero-copy view:
//! every value borrows the input buffer.
//!
//! # Authorship
//!
//! [`decode_plain`] only accepts types the server may author without keys;
//! [`decode_sealed`] only accepts types that arrive inside an AEAD envelope.
//! `STREAM_DATA` is raw sealed bytes and is handled by the fragment layer, so
//! both decoders reject it with [`MessageError::WrongEncoding`] (44 §3.1).
//!
//! No signature verification happens here. The AEAD envelope authenticates
//! the body; [`Ordered::canonical_bytes_excluding`] only serves callers that
//! need a stable byte view (44 §4.6, INV-24).

use std::collections::{HashMap, VecDeque};
use std::fmt;

use crate::protocol::MAX_FIELDS;
use crate::protocol::crypto::DETACHED_OVERHEAD;
use crate::protocol::errors::{KickReason, SyncEndReason, TrnReason};
use crate::protocol::frame::{
    BodyEncoding, ClientId, Limits, MsgType, OpId, PrefixKind, Seq, SessionId,
};
use crate::protocol::version::{Caps, ProtoVersion, WcpVer};

/// WCP field identifiers (44 appendix B).
///
/// The ids are frozen: `F_WCP_VER` is always the first field, and every
/// payload decoder depends on these exact values. Unknown ids are preserved
/// by [`FieldMap`] and ignored by decoders (44 R7).
pub mod fid {
    /// WCP version, `u16`; must be the first field.
    pub const F_WCP_VER: u8 = 0x01;
    /// Transport reason, `u16` (`ERROR`).
    pub const F_TRN_REASON: u8 = 0x02;
    /// Human-readable detail, bytes (`ERROR`, `SYNC_END`).
    pub const F_DETAIL: u8 = 0x03;
    /// Capability bits, `u32` (`HELLO`, `WELCOME`).
    pub const F_CAPS: u8 = 0x04;
    /// Kick reason, `u16` (`KICK`).
    pub const F_KICK_REASON: u8 = 0x05;
    /// Sync-end reason, `u8` (`SYNC_END`).
    pub const F_SYNC_REASON: u8 = 0x06;
    /// Leave reason, `u8` (`LEAVE` 0x1B).
    pub const F_LEAVE_REASON: u8 = 0x07;
    /// Flow-control grant, `u32` (`FLOW`).
    pub const F_GRANT_BYTES: u8 = 0x08;
    /// Server clock in nanoseconds or seconds, `u64` (`PONG`, `WELCOME`).
    pub const F_SERVER_TIME: u8 = 0x09;
    /// Resync mode, `u8` (`WELCOME`).
    pub const F_RESYNC: u8 = 0x0A;
    /// Nested `WelcomeLimits` (`WELCOME`).
    pub const F_LIMITS: u8 = 0x0B;
    /// Session identifier, 16 B (`WELCOME`, `ERROR`).
    pub const F_SESSION_ID: u8 = 0x0D;
    /// Operation identifier, 16 B (`ORDERED`).
    pub const F_OP_ID: u8 = 0x10;
    /// Operation class, `u8` (`ORDERED`).
    pub const F_OP_CLASS: u8 = 0x11;
    /// Absolute path, UTF-8 (`ORDERED`).
    pub const F_PATH: u8 = 0x12;
    /// Second path, UTF-8 (`RENAME`).
    pub const F_PATH2: u8 = 0x13;
    /// Mode bits, `u32` (`SETATTR`, `MKDIR`, `CREATE_EXCL`).
    pub const F_MODE: u8 = 0x14;
    /// Owner uid, `u32` (`ORDERED` file ops).
    pub const F_UID: u8 = 0x15;
    /// Owner gid, `u32` (`ORDERED` file ops).
    pub const F_GID: u8 = 0x16;
    /// Modification time in nanoseconds, `u64` (`ORDERED` file ops).
    pub const F_MTIME_NS: u8 = 0x17;
    /// Write offset, `u64` (`PWRITE`).
    pub const F_OFFSET: u8 = 0x18;
    /// Truncate length, `u64` (`TRUNCATE`).
    pub const F_LENGTH: u8 = 0x19;
    /// Data session identifier, 16 B (`WRITE`, `PWRITE`).
    pub const F_DATA_SESSION: u8 = 0x1A;
    /// Total plaintext length, `u64` (`WRITE`, `PWRITE`).
    pub const F_TOTAL_LEN: u8 = 0x1B;
    /// Lock type, `u8` (`FLOCK`, `FCNTL_LOCK`).
    pub const F_LOCK_TYPE: u8 = 0x1D;
    /// Lock action, `u8` (`FLOCK`, `FCNTL_LOCK`).
    pub const F_LOCK_ACTION: u8 = 0x1E;
    /// Lock range start, `u64` (`FCNTL_LOCK`).
    pub const F_LOCK_START: u8 = 0x1F;
    /// Lock range length, `u64` (`FCNTL_LOCK`).
    pub const F_LOCK_LEN: u8 = 0x20;
    /// Symlink target or hard-link source, UTF-8 (`LINK`, `SYMLINK`).
    pub const F_TARGET: u8 = 0x21;
    /// Concatenated 16 B op ids (`ACK`).
    pub const F_OP_IDS: u8 = 0x22;
    /// Client clock, `u64` (`PING`).
    pub const F_CLIENT_TIME: u8 = 0x23;
    /// Open/create flags, `u32` (`CREATE_EXCL`).
    pub const F_OP_FLAGS: u8 = 0x24;
    /// Last acknowledged sequence, `u64` (`LEAVE`).
    pub const F_LAST_SIGNED_SEQ: u8 = 0x2B;
    /// Data-stream hash, 32 B (`WRITE`, `PWRITE`).
    pub const F_DATA_HASH: u8 = 0x2C;
    /// Protocol major, `u16` (`HELLO`, `WELCOME`).
    pub const F_PROTO_MAJOR: u8 = 0x30;
    /// Protocol minor, `u16` (`HELLO`, `WELCOME`).
    pub const F_PROTO_MINOR: u8 = 0x31;
    /// Server epoch, `u64` (`WELCOME`).
    pub const F_EPOCH: u8 = 0x32;
    /// Current server sequence, `u64` (`WELCOME`).
    pub const F_CURRENT_SEQ: u8 = 0x33;
    /// Client identifier, 16 B (`HELLO`, `WELCOME`, `ORDERED`).
    pub const F_CLIENT_ID: u8 = 0x34;
    /// Client nonce, 32 B (`HELLO`).
    pub const F_CLIENT_NONCE: u8 = 0x35;
    /// Server nonce, 32 B (`WELCOME`).
    pub const F_SERVER_NONCE: u8 = 0x38;
    /// Relay sub-message kind, `u8` (`RELAY`).
    pub const F_SUB_KIND: u8 = 0x40;
    /// Vendor extension, bytes.
    pub const F_EXTRA: u8 = 0x7F;

    // The nested WCP streams in 44 appendix B carry no field ids of their own.
    // These ids are frozen here so that `WelcomeLimits` is unambiguous on the
    // wire; they live inside the nested stream and never appear at the top
    // level.
    /// `WelcomeLimits.max_frame`, `u32`.
    pub const F_LIMIT_MAX_FRAME: u8 = 0x50;
    /// `WelcomeLimits.credit_bytes`, `u32`.
    pub const F_LIMIT_CREDIT_BYTES: u8 = 0x51;
    /// `WelcomeLimits.session_ttl_s`, `u32`.
    pub const F_LIMIT_SESSION_TTL_S: u8 = 0x52;
    /// `WelcomeLimits.max_sessions`, `u32`.
    pub const F_LIMIT_MAX_SESSIONS: u8 = 0x53;
    /// Server proof over the canonical `WELCOME` body, 61 B (`WELCOME`).
    ///
    /// `alg u8 | nonce 12 | ciphertext 32 | tag 16`, sealed under the
    /// handshake key. The plaintext is `BLAKE3(canonical body excluding this
    /// field)`; the AAD is `"sm/v2/welcome\0" ‖ client_nonce`.
    pub const F_SERVER_PROOF: u8 = 0x5E;
    /// Sealed `AUTH` sub-body, 85 B (`HELLO`).
    ///
    /// `alg u8 | nonce 12 | ciphertext 56 | tag 16`, sealed under the
    /// client-nonce handshake key. The AAD is
    /// `"sm/v2/auth\0" ‖ client_nonce ‖ ctrl_prefix`.
    pub const F_AUTH: u8 = 0x5F;
    /// Sealed `ACCEPT` sub-body, 61 B (`WELCOME`).
    ///
    /// `alg u8 | nonce 12 | ciphertext 32 | tag 16`, sealed under the
    /// two-nonce handshake key. The AAD is
    /// `"sm/v2/accept\0" ‖ client_nonce ‖ server_nonce`.
    pub const F_SEALED_ACCEPT: u8 = 0x5C;
}

/// Width of the sealed `AUTH` carried in `HELLO`.
pub const AUTH_SEALED_LEN: usize = DETACHED_OVERHEAD + Auth::LEN;

/// Width of the sealed `ACCEPT` carried in `WELCOME`.
pub const ACCEPT_SEALED_LEN: usize = DETACHED_OVERHEAD + Accept::LEN;

/// A WCP encoding or decoding failure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WcpError {
    /// The body exceeds `limits.wcp_max`.
    TooLarge {
        /// Actual body length.
        len: usize,
        /// Configured maximum.
        max: usize,
    },
    /// More than [`MAX_FIELDS`] fields are present.
    TooManyFields {
        /// Observed field count.
        count: usize,
        /// Configured maximum.
        max: usize,
    },
    /// The first field is not `F_WCP_VER`.
    MissingVersion,
    /// The version's major byte is not 1.
    UnsupportedVersion(u16),
    /// The same fid appears twice.
    DuplicateField(u8),
    /// A field header or value is truncated.
    Malformed {
        /// Offset of the malformed field.
        offset: usize,
    },
    /// A required field is absent.
    MissingField(u8),
    /// A fixed-width field has the wrong length.
    BadFieldLen {
        /// Field id.
        fid: u8,
        /// Required length.
        need: usize,
        /// Observed length.
        got: usize,
    },
    /// A field value cannot be encoded with a `u16` length.
    FieldTooLong {
        /// Field id.
        fid: u8,
        /// Observed length.
        len: usize,
        /// Maximum encodable length.
        max: usize,
    },
    /// A string field is not valid UTF-8.
    BadUtf8(u8),
    /// A string field contains a NUL byte.
    NulInString(u8),
    /// Nested WCP depth exceeded the v1 limit.
    DepthExceeded,
}

impl fmt::Display for WcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { len, max } => {
                write!(f, "WCP body is {len} bytes, maximum {max}")
            }
            Self::TooManyFields { count, max } => {
                write!(f, "WCP body has {count} fields, maximum {max}")
            }
            Self::MissingVersion => f.write_str("WCP body does not start with F_WCP_VER"),
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported WCP version 0x{v:04x}")
            }
            Self::DuplicateField(id) => write!(f, "duplicate WCP field 0x{id:02x}"),
            Self::Malformed { offset } => {
                write!(f, "malformed WCP field at offset {offset}")
            }
            Self::MissingField(id) => write!(f, "missing WCP field 0x{id:02x}"),
            Self::BadFieldLen { fid, need, got } => {
                write!(f, "WCP field 0x{fid:02x} is {got} bytes, expected {need}")
            }
            Self::FieldTooLong { fid, len, max } => {
                write!(f, "WCP field 0x{fid:02x} is {len} bytes, maximum {max}")
            }
            Self::BadUtf8(id) => write!(f, "WCP field 0x{id:02x} is not UTF-8"),
            Self::NulInString(id) => write!(f, "WCP field 0x{id:02x} contains NUL"),
            Self::DepthExceeded => f.write_str("WCP nesting depth exceeded"),
        }
    }
}

impl std::error::Error for WcpError {}

/// A canonical-path validation failure (44 §3.5, INV-18).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PathError {
    /// The path is empty.
    Empty,
    /// The path does not start with `/`.
    NotAbsolute,
    /// The path ends with `/` and is not the root.
    TrailingSlash,
    /// The path contains `//`.
    EmptySegment,
    /// The path contains a `.` segment.
    DotSegment,
    /// The path contains a `..` segment.
    ParentSegment,
    /// The path contains a NUL byte.
    Nul,
    /// The path exceeds the configured maximum.
    TooLong {
        /// Actual length.
        len: usize,
        /// Configured maximum.
        max: usize,
    },
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("path is empty"),
            Self::NotAbsolute => f.write_str("path is not absolute"),
            Self::TrailingSlash => f.write_str("path has a trailing slash"),
            Self::EmptySegment => f.write_str("path has an empty segment"),
            Self::DotSegment => f.write_str("path has a '.' segment"),
            Self::ParentSegment => f.write_str("path has a '..' segment"),
            Self::Nul => f.write_str("path contains NUL"),
            Self::TooLong { len, max } => {
                write!(f, "path is {len} bytes, maximum {max}")
            }
        }
    }
}

impl std::error::Error for PathError {}

/// A validated absolute path inside the mount namespace.
///
/// Construction only validates; it never rewrites (INV-18). Rewriting would
/// let two clients derive different `path_hash` values from the same input
/// (44 R8).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WirePath<'a>(&'a str);

impl<'a> WirePath<'a> {
    /// Validate `raw` against the canonical-path rules.
    ///
    /// Rules: absolute, root is `/`, no trailing slash otherwise, no empty
    /// segment, no `.` or `..` segment, no NUL, at most `max` bytes. UTF-8 is
    /// guaranteed by `&str`.
    pub fn parse(raw: &'a str, max: usize) -> Result<Self, PathError> {
        if raw.is_empty() {
            return Err(PathError::Empty);
        }
        if raw.len() > max {
            return Err(PathError::TooLong {
                len: raw.len(),
                max,
            });
        }
        if raw.as_bytes().contains(&0) {
            return Err(PathError::Nul);
        }
        if !raw.starts_with('/') {
            return Err(PathError::NotAbsolute);
        }
        if raw == "/" {
            return Ok(Self(raw));
        }
        if raw.ends_with('/') {
            return Err(PathError::TrailingSlash);
        }
        for segment in raw[1..].split('/') {
            if segment.is_empty() {
                return Err(PathError::EmptySegment);
            }
            if segment == "." {
                return Err(PathError::DotSegment);
            }
            if segment == ".." {
                return Err(PathError::ParentSegment);
            }
        }
        Ok(Self(raw))
    }

    /// The canonical path text.
    pub fn as_str(&self) -> &'a str {
        self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always false: [`WirePath::parse`] rejects the empty path. Present so
    /// that `len` has its conventional counterpart.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `BLAKE3(canonical path bytes)` for log correlation only (44 §3.5).
    ///
    /// Not used for routing or AAD.
    pub fn hash(&self) -> [u8; 32] {
        *blake3::hash(self.0.as_bytes()).as_bytes()
    }
}

impl fmt::Debug for WirePath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 44 §2.8: paths never reach logs in clear text. The hash prefix is
        // enough to correlate entries without leaking user content.
        let hash = self.hash();
        write!(
            f,
            "WirePath(len={}, hash={:02x}{:02x}{:02x}{:02x})",
            self.0.len(),
            hash[0],
            hash[1],
            hash[2],
            hash[3]
        )
    }
}

/// Operation class carried in `F_OP_CLASS` (44 §3.2).
///
/// Unknown values are fatal: skipping an op class would fork the replicated
/// state with no replay window to heal it (49 A14, 44 D9).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpClass(u8);

impl OpClass {
    /// Write a whole data stream.
    pub const WRITE: Self = Self(1);
    /// Write at an offset.
    pub const PWRITE: Self = Self(2);
    /// Truncate to a length.
    pub const TRUNCATE: Self = Self(3);
    /// Change metadata.
    pub const SETATTR: Self = Self(4);
    /// Rename a path.
    pub const RENAME: Self = Self(5);
    /// Remove a directory entry.
    pub const UNLINK: Self = Self(6);
    /// Create a directory.
    pub const MKDIR: Self = Self(7);
    /// Remove a directory.
    pub const RMDIR: Self = Self(8);
    /// Hard link.
    pub const LINK: Self = Self(9);
    /// Symbolic link.
    pub const SYMLINK: Self = Self(10);
    /// Create exclusively.
    pub const CREATE_EXCL: Self = Self(11);
    /// BSD-style lock.
    pub const FLOCK: Self = Self(12);
    /// POSIX record lock.
    pub const FCNTL_LOCK: Self = Self(13);
    /// Synchronization control. Unused in v3.
    pub const SYNC_CTRL: Self = Self(14);
    /// Graceful leave.
    pub const LEAVE: Self = Self(15);

    /// Every defined class, in wire order.
    pub const ALL: [Self; 15] = [
        Self::WRITE,
        Self::PWRITE,
        Self::TRUNCATE,
        Self::SETATTR,
        Self::RENAME,
        Self::UNLINK,
        Self::MKDIR,
        Self::RMDIR,
        Self::LINK,
        Self::SYMLINK,
        Self::CREATE_EXCL,
        Self::FLOCK,
        Self::FCNTL_LOCK,
        Self::SYNC_CTRL,
        Self::LEAVE,
    ];

    /// Decode a wire value. Values outside `1..=15` are fatal.
    pub fn from_u8(raw: u8) -> Result<Self, MessageError> {
        match raw {
            1..=15 => Ok(Self(raw)),
            other => Err(MessageError::UnknownOpClass(other)),
        }
    }

    /// Raw wire value.
    pub const fn get(self) -> u8 {
        self.0
    }

    /// Stable name for logs.
    pub const fn name(self) -> &'static str {
        match self.0 {
            1 => "WRITE",
            2 => "PWRITE",
            3 => "TRUNCATE",
            4 => "SETATTR",
            5 => "RENAME",
            6 => "UNLINK",
            7 => "MKDIR",
            8 => "RMDIR",
            9 => "LINK",
            10 => "SYMLINK",
            11 => "CREATE_EXCL",
            12 => "FLOCK",
            13 => "FCNTL_LOCK",
            14 => "SYNC_CTRL",
            15 => "LEAVE",
            _ => "UNKNOWN",
        }
    }

    /// Whether this class mutates a filesystem object (classes 1..=14).
    pub const fn is_file_op(self) -> bool {
        self.0 >= 1 && self.0 <= 14
    }

    /// Whether `ORDERED` must carry `F_PATH`, `F_MTIME_NS`, `F_UID`, `F_GID`.
    pub const fn requires_file_attrs(self) -> bool {
        self.is_file_op()
    }

    /// Whether this is a leave (15).
    pub const fn is_leave(self) -> bool {
        self.0 == 15
    }
}

impl fmt::Debug for OpClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OpClass({}:{})", self.name(), self.0)
    }
}

/// A message decoding failure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageError {
    /// WCP parsing failed.
    Wcp(WcpError),
    /// Path validation failed.
    Path(PathError),
    /// `F_OP_CLASS` is outside `1..=15`; fatal (49 A14).
    UnknownOpClass(u8),
    /// `F_SUB_KIND` is not a known relay sub-message kind.
    UnknownRelaySub(u8),
    /// `F_RESYNC` is neither `0` (none) nor `2` (full).
    UnknownResync(u8),
    /// `F_TRN_REASON` is unknown.
    UnknownTrnReason(u16),
    /// `F_KICK_REASON` is unknown.
    UnknownKickReason(u16),
    /// `F_SYNC_REASON` is unknown.
    UnknownSyncReason(u8),
    /// The message type does not use this body encoding.
    WrongEncoding(MsgType),
    /// The peer announced a protocol major this build does not speak.
    ///
    /// This is a version rejection, not a parse failure: it is raised from
    /// the two version fields alone, before fields that only the current
    /// wire format carries are required.
    ProtocolVersion {
        /// Major this build requires.
        local: u16,
        /// Major the peer announced.
        remote: u16,
    },
    /// `F_OP_IDS` is not a whole number of 16-byte ids.
    BadOpIdsLen(usize),
    /// A field is present but forbidden or malformed in context.
    BadValue {
        /// Offending field id.
        fid: u8,
        /// Static explanation.
        reason: &'static str,
    },
    /// The body is shorter than the message requires.
    BodyTooShort {
        /// Observed length.
        len: usize,
        /// Required minimum.
        min: usize,
    },
    /// A fixed-layout body has the wrong exact width.
    BadBodyLen {
        /// Observed length.
        len: usize,
        /// Required exact length.
        need: usize,
    },
}

impl MessageError {
    /// Whether the error must stop the connection or the sync session.
    ///
    /// An unknown `op_class` is fatal: ignoring it would fork state with no
    /// replay window (49 A14). A protocol major mismatch is fatal because no
    /// compatible mode exists. Unknown fids are ignored, not fatal (44 R7).
    pub const fn is_fatal(self) -> bool {
        matches!(self, Self::UnknownOpClass(_) | Self::ProtocolVersion { .. })
    }
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wcp(e) => write!(f, "{e}"),
            Self::Path(e) => write!(f, "{e}"),
            Self::UnknownOpClass(raw) => write!(f, "unknown op_class {raw}"),
            Self::UnknownRelaySub(raw) => write!(f, "unknown relay sub-kind {raw}"),
            Self::UnknownResync(raw) => write!(f, "unknown resync mode {raw}"),
            Self::UnknownTrnReason(raw) => write!(f, "unknown transport reason {raw}"),
            Self::UnknownKickReason(raw) => write!(f, "unknown kick reason {raw}"),
            Self::UnknownSyncReason(raw) => write!(f, "unknown sync-end reason {raw}"),
            Self::WrongEncoding(ty) => {
                write!(f, "{} cannot use this body encoding", ty.name())
            }
            Self::ProtocolVersion { local, remote } => {
                write!(f, "protocol major mismatch: local {local}, remote {remote}")
            }
            Self::BadOpIdsLen(len) => {
                write!(f, "F_OP_IDS length {len} is not a multiple of 16")
            }
            Self::BadValue { fid, reason } => {
                write!(f, "bad value for field 0x{fid:02x}: {reason}")
            }
            Self::BodyTooShort { len, min } => {
                write!(f, "body is {len} bytes, minimum {min}")
            }
            Self::BadBodyLen { len, need } => {
                write!(f, "body is {len} bytes, exactly {need} required")
            }
        }
    }
}

impl std::error::Error for MessageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wcp(e) => Some(e),
            Self::Path(e) => Some(e),
            _ => None,
        }
    }
}

impl From<WcpError> for MessageError {
    fn from(value: WcpError) -> Self {
        Self::Wcp(value)
    }
}

impl From<PathError> for MessageError {
    fn from(value: PathError) -> Self {
        Self::Path(value)
    }
}

/// A zero-copy view of one WCP body.
///
/// Values borrow the input buffer; parsing never allocates. `Debug` prints
/// only `fid:len` so that logs cannot leak user content (44 R5).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FieldMap<'a> {
    fields: [(u8, &'a [u8]); MAX_FIELDS],
    len: u8,
    buf: &'a [u8],
    ver: WcpVer,
}

impl<'a> FieldMap<'a> {
    /// Parse a WCP body.
    ///
    /// The first field must be `F_WCP_VER` with length 2. Fields may appear
    /// in any order; duplicates are rejected; unknown fids are preserved.
    pub fn parse(buf: &'a [u8], limits: &Limits) -> Result<Self, WcpError> {
        let max = usize::from(limits.wcp_max);
        if buf.len() > max {
            return Err(WcpError::TooLarge {
                len: buf.len(),
                max,
            });
        }
        let mut fields: [(u8, &'a [u8]); MAX_FIELDS] = [(0, &[]); MAX_FIELDS];
        let mut len = 0usize;
        let mut ver = WcpVer::CURRENT;
        let mut offset = 0usize;
        while offset < buf.len() {
            if buf.len() - offset < 3 {
                return Err(WcpError::Malformed { offset });
            }
            let field_id = buf[offset];
            let value_len = usize::from(u16::from_le_bytes([buf[offset + 1], buf[offset + 2]]));
            let start = offset + 3;
            let Some(end) = start.checked_add(value_len) else {
                return Err(WcpError::Malformed { offset });
            };
            if end > buf.len() {
                return Err(WcpError::Malformed { offset });
            }
            let value = &buf[start..end];
            if len == 0 {
                if field_id != fid::F_WCP_VER {
                    return Err(WcpError::MissingVersion);
                }
                if value.len() != 2 {
                    return Err(WcpError::BadFieldLen {
                        fid: field_id,
                        need: 2,
                        got: value.len(),
                    });
                }
                let raw = u16::from_le_bytes([value[0], value[1]]);
                ver = WcpVer::parse(raw).map_err(|_| WcpError::UnsupportedVersion(raw))?;
            }
            if fields[..len]
                .iter()
                .any(|(existing, _)| *existing == field_id)
            {
                return Err(WcpError::DuplicateField(field_id));
            }
            if len == MAX_FIELDS {
                return Err(WcpError::TooManyFields {
                    count: len + 1,
                    max: MAX_FIELDS,
                });
            }
            fields[len] = (field_id, value);
            len += 1;
            offset = end;
        }
        if len == 0 {
            return Err(WcpError::MissingVersion);
        }
        Ok(Self {
            fields,
            len: len as u8,
            buf,
            ver,
        })
    }

    /// Borrow a field value.
    pub fn get(&self, field_id: u8) -> Option<&'a [u8]> {
        self.fields[..usize::from(self.len)]
            .iter()
            .find(|(existing, _)| *existing == field_id)
            .map(|&(_, value)| value)
    }

    /// Require a field value.
    pub fn require(&self, field_id: u8) -> Result<&'a [u8], WcpError> {
        self.get(field_id).ok_or(WcpError::MissingField(field_id))
    }

    /// The original body bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.buf
    }

    /// Number of fields.
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// Whether the map has no fields. A parsed map always has at least
    /// `F_WCP_VER`.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Iterate `(fid, value)` in wire order.
    pub fn iter(&self) -> impl Iterator<Item = (u8, &'a [u8])> + '_ {
        self.fields[..usize::from(self.len)].iter().copied()
    }

    /// The WCP version from the first field.
    pub fn version(&self) -> WcpVer {
        self.ver
    }

    /// A field that must be exactly `N` bytes.
    pub fn fixed<const N: usize>(&self, field_id: u8) -> Result<Option<[u8; N]>, WcpError> {
        self.exact(field_id)
    }

    /// A `u8` field.
    pub fn u8(&self, field_id: u8) -> Result<Option<u8>, WcpError> {
        Ok(self.exact::<1>(field_id)?.map(|bytes| bytes[0]))
    }

    /// A `u16` field.
    pub fn u16(&self, field_id: u8) -> Result<Option<u16>, WcpError> {
        Ok(self.exact::<2>(field_id)?.map(u16::from_le_bytes))
    }

    /// A `u32` field.
    pub fn u32(&self, field_id: u8) -> Result<Option<u32>, WcpError> {
        Ok(self.exact::<4>(field_id)?.map(u32::from_le_bytes))
    }

    /// A `u64` field.
    pub fn u64(&self, field_id: u8) -> Result<Option<u64>, WcpError> {
        Ok(self.exact::<8>(field_id)?.map(u64::from_le_bytes))
    }

    /// A UTF-8 string field with no NUL bytes.
    pub fn str(&self, field_id: u8) -> Result<Option<&'a str>, WcpError> {
        match self.get(field_id) {
            None => Ok(None),
            Some(value) => {
                let text = std::str::from_utf8(value).map_err(|_| WcpError::BadUtf8(field_id))?;
                if text.as_bytes().contains(&0) {
                    return Err(WcpError::NulInString(field_id));
                }
                Ok(Some(text))
            }
        }
    }

    /// Re-encode every field except `exclude`, sorted by fid.
    ///
    /// This is the canonical op-body form (44 §4.6, INV-24). Hashing is not
    /// done here.
    pub fn canonical_bytes_excluding(&self, exclude: &[u8]) -> Result<Vec<u8>, WcpError> {
        let mut selected: Vec<(u8, &'a [u8])> = self
            .iter()
            .filter(|(field_id, _)| !exclude.contains(field_id))
            .collect();
        selected.sort_by_key(|(field_id, _)| *field_id);
        let mut out = Vec::new();
        for (field_id, value) in selected {
            append_field(&mut out, field_id, value)?;
        }
        Ok(out)
    }

    fn exact<const N: usize>(&self, field_id: u8) -> Result<Option<[u8; N]>, WcpError> {
        match self.get(field_id) {
            None => Ok(None),
            Some(value) => {
                if value.len() != N {
                    return Err(WcpError::BadFieldLen {
                        fid: field_id,
                        need: N,
                        got: value.len(),
                    });
                }
                let mut bytes = [0u8; N];
                bytes.copy_from_slice(value);
                Ok(Some(bytes))
            }
        }
    }
}

impl fmt::Debug for FieldMap<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FieldMap{")?;
        for (index, (field_id, value)) in self.iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{field_id}:{}", value.len())?;
        }
        f.write_str("}")
    }
}

/// A WCP encoder with canonical (sorted) output.
///
/// `new` always writes `F_WCP_VER = 1` and cannot fail. `finish` validates
/// duplicates, the field cap and the 64 KiB body cap.
pub struct WcpWriter {
    fields: Vec<(u8, WcpValue)>,
}

enum WcpValue {
    Bytes(Vec<u8>),
    Nested(Vec<(u8, WcpValue)>),
}

impl WcpWriter {
    /// Start a WCP stream with `F_WCP_VER = 1`.
    pub fn new() -> Self {
        Self {
            fields: vec![(
                fid::F_WCP_VER,
                WcpValue::Bytes(WcpVer::CURRENT.get().to_le_bytes().to_vec()),
            )],
        }
    }

    /// Append a `u8` field.
    pub fn u8(&mut self, field_id: u8, value: u8) -> &mut Self {
        self.raw(field_id, &[value])
    }

    /// Append a `u16` field.
    pub fn u16(&mut self, field_id: u8, value: u16) -> &mut Self {
        self.raw(field_id, &value.to_le_bytes())
    }

    /// Append a `u32` field.
    pub fn u32(&mut self, field_id: u8, value: u32) -> &mut Self {
        self.raw(field_id, &value.to_le_bytes())
    }

    /// Append a `u64` field.
    pub fn u64(&mut self, field_id: u8, value: u64) -> &mut Self {
        self.raw(field_id, &value.to_le_bytes())
    }

    /// Append a bytes field.
    pub fn bytes(&mut self, field_id: u8, value: &[u8]) -> &mut Self {
        self.raw(field_id, value)
    }

    /// Append a UTF-8 field.
    pub fn str(&mut self, field_id: u8, value: &str) -> &mut Self {
        self.raw(field_id, value.as_bytes())
    }

    /// Append a nested WCP stream. The child always carries its own
    /// `F_WCP_VER`, so nesting depth is visible on the wire (44 §3.3).
    pub fn nested(&mut self, field_id: u8, build: impl FnOnce(&mut WcpWriter)) -> &mut Self {
        let mut child = Self::new();
        build(&mut child);
        self.fields.push((field_id, WcpValue::Nested(child.fields)));
        self
    }

    /// Validate and encode, sorted by fid.
    pub fn finish(self) -> Result<Vec<u8>, WcpError> {
        encode_fields(&self.fields)
    }

    fn raw(&mut self, field_id: u8, value: &[u8]) -> &mut Self {
        self.fields
            .push((field_id, WcpValue::Bytes(value.to_vec())));
        self
    }
}

impl Default for WcpWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for WcpWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WcpWriter({} fields)", self.fields.len())
    }
}

fn encode_fields(fields: &[(u8, WcpValue)]) -> Result<Vec<u8>, WcpError> {
    if fields.len() > MAX_FIELDS {
        return Err(WcpError::TooManyFields {
            count: fields.len(),
            max: MAX_FIELDS,
        });
    }
    for (index, (field_id, _)) in fields.iter().enumerate() {
        if fields[..index]
            .iter()
            .any(|(earlier, _)| earlier == field_id)
        {
            return Err(WcpError::DuplicateField(*field_id));
        }
    }
    let mut order: Vec<&(u8, WcpValue)> = fields.iter().collect();
    order.sort_by_key(|(field_id, _)| *field_id);
    let mut out = Vec::new();
    for (field_id, value) in order {
        match value {
            WcpValue::Bytes(bytes) => append_field(&mut out, *field_id, bytes)?,
            WcpValue::Nested(children) => {
                let nested = encode_fields(children)?;
                append_field(&mut out, *field_id, &nested)?;
            }
        }
    }
    Ok(out)
}

fn append_field(out: &mut Vec<u8>, field_id: u8, value: &[u8]) -> Result<(), WcpError> {
    if value.len() > usize::from(u16::MAX) {
        return Err(WcpError::FieldTooLong {
            fid: field_id,
            len: value.len(),
            max: usize::from(u16::MAX),
        });
    }
    let total = out.len().saturating_add(3).saturating_add(value.len());
    if total > usize::from(u16::MAX) {
        return Err(WcpError::TooLarge {
            len: total,
            max: usize::from(u16::MAX),
        });
    }
    out.push(field_id);
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn required<T>(value: Option<T>, field_id: u8) -> Result<T, MessageError> {
    value.ok_or(MessageError::Wcp(WcpError::MissingField(field_id)))
}

fn path_field<'a>(
    fields: &FieldMap<'a>,
    field_id: u8,
    limits: &Limits,
) -> Result<WirePath<'a>, MessageError> {
    let raw = required(fields.str(field_id)?, field_id)?;
    Ok(WirePath::parse(raw, usize::from(limits.path_max))?)
}

/// Resync mode carried in `F_RESYNC` (44 §3.4).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum ResyncMode {
    /// No resync needed.
    None = 0,
    /// Full replay from the compacted event stream.
    Full = 2,
}

impl ResyncMode {
    /// Decode a wire value. Unknown values are fatal for the join.
    pub fn from_u8(raw: u8) -> Result<Self, MessageError> {
        match raw {
            0 => Ok(Self::None),
            2 => Ok(Self::Full),
            other => Err(MessageError::UnknownResync(other)),
        }
    }

    /// Raw wire value.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Limits nested in `WELCOME` under `F_LIMITS`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct WelcomeLimits {
    /// Largest accepted frame.
    pub max_frame: u32,
    /// Flow-control credit window.
    pub credit_bytes: u32,
    /// Session time-to-live in seconds.
    pub session_ttl_s: u32,
    /// Maximum concurrent sessions.
    pub max_sessions: u32,
}

impl WelcomeLimits {
    fn decode(body: &[u8], limits: &Limits) -> Result<Self, MessageError> {
        let fields = FieldMap::parse(body, limits)?;
        Ok(Self {
            max_frame: required(fields.u32(fid::F_LIMIT_MAX_FRAME)?, fid::F_LIMIT_MAX_FRAME)?,
            credit_bytes: required(
                fields.u32(fid::F_LIMIT_CREDIT_BYTES)?,
                fid::F_LIMIT_CREDIT_BYTES,
            )?,
            session_ttl_s: required(
                fields.u32(fid::F_LIMIT_SESSION_TTL_S)?,
                fid::F_LIMIT_SESSION_TTL_S,
            )?,
            max_sessions: required(
                fields.u32(fid::F_LIMIT_MAX_SESSIONS)?,
                fid::F_LIMIT_MAX_SESSIONS,
            )?,
        })
    }

    fn write(&self, writer: &mut WcpWriter) {
        writer.u32(fid::F_LIMIT_MAX_FRAME, self.max_frame);
        writer.u32(fid::F_LIMIT_CREDIT_BYTES, self.credit_bytes);
        writer.u32(fid::F_LIMIT_SESSION_TTL_S, self.session_ttl_s);
        writer.u32(fid::F_LIMIT_MAX_SESSIONS, self.max_sessions);
    }
}

/// File attributes that every file op carries (44 §3.2).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FileAttrs {
    /// Modification time in nanoseconds.
    pub mtime_ns: u64,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
}

/// A reference to a data stream carried by `WRITE`/`PWRITE`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct DataRef {
    /// Data session identifier.
    pub session: SessionId,
    /// Total plaintext length.
    pub total_len: u64,
    /// `BLAKE3` of the plaintext stream.
    pub data_hash: [u8; 32],
}

/// `HELLO` body: plain WCP with a sealed `AUTH` (44 §3.4).
///
/// The header fields stay readable before a key is live. `auth` is the
/// client's proof of PSK possession, sealed under a key derived from the PSK
/// and `client_nonce`, so one client flight completes authentication.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Hello {
    /// Protocol version.
    pub proto: ProtoVersion,
    /// Capability bits.
    pub caps: Caps,
    /// Persistent client identifier.
    pub client_id: ClientId,
    /// 32-byte client nonce for the join proof.
    pub client_nonce: [u8; 32],
    /// Sealed `AUTH` body.
    pub auth: [u8; AUTH_SEALED_LEN],
}

impl Hello {
    /// Build a hello body.
    pub const fn new(
        proto: ProtoVersion,
        caps: Caps,
        client_id: ClientId,
        client_nonce: [u8; 32],
        auth: [u8; AUTH_SEALED_LEN],
    ) -> Self {
        Self {
            proto,
            caps,
            client_id,
            client_nonce,
            auth,
        }
    }

    /// Decode a plain `HELLO` body.
    ///
    /// This is a pure parse. Version policy lives in [`decode_plain`], which
    /// rejects an older major before it requires `F_AUTH`.
    pub fn decode(body: &[u8], limits: &Limits) -> Result<Self, MessageError> {
        Self::decode_fields(FieldMap::parse(body, limits)?)
    }

    fn decode_fields(fields: FieldMap<'_>) -> Result<Self, MessageError> {
        Ok(Self {
            proto: ProtoVersion {
                major: required(fields.u16(fid::F_PROTO_MAJOR)?, fid::F_PROTO_MAJOR)?,
                minor: required(fields.u16(fid::F_PROTO_MINOR)?, fid::F_PROTO_MINOR)?,
            },
            caps: Caps::from_bits(required(fields.u32(fid::F_CAPS)?, fid::F_CAPS)?),
            client_id: ClientId::from_bytes(required(
                fields.fixed::<16>(fid::F_CLIENT_ID)?,
                fid::F_CLIENT_ID,
            )?),
            client_nonce: required(
                fields.fixed::<32>(fid::F_CLIENT_NONCE)?,
                fid::F_CLIENT_NONCE,
            )?,
            auth: required(fields.fixed::<AUTH_SEALED_LEN>(fid::F_AUTH)?, fid::F_AUTH)?,
        })
    }

    /// Encode a plain `HELLO` body.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        let mut writer = WcpWriter::new();
        writer.u16(fid::F_PROTO_MAJOR, self.proto.major);
        writer.u16(fid::F_PROTO_MINOR, self.proto.minor);
        writer.u32(fid::F_CAPS, self.caps.bits());
        writer.bytes(fid::F_CLIENT_ID, &self.client_id.to_bytes());
        writer.bytes(fid::F_CLIENT_NONCE, &self.client_nonce);
        writer.bytes(fid::F_AUTH, &self.auth);
        Ok(writer.finish()?)
    }
}

/// `WELCOME` body: plain WCP (44 §3.4, 44 D5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Welcome {
    /// Protocol version.
    pub proto: ProtoVersion,
    /// Capability bits.
    pub caps: Caps,
    /// Server epoch.
    pub epoch: u64,
    /// Current server sequence.
    pub current_seq: Seq,
    /// Echoed client identifier.
    pub client_id: ClientId,
    /// Requested resync mode.
    pub resync: ResyncMode,
    /// Server-side limits.
    pub limits: WelcomeLimits,
    /// Server clock.
    pub server_time: u64,
    /// 32-byte server nonce.
    pub server_nonce: [u8; 32],
    /// Join session.
    pub session_id: SessionId,
}

impl Welcome {
    /// Width of the `F_SERVER_PROOF` value.
    pub const SERVER_PROOF_LEN: usize = 61;

    /// Decode a plain `WELCOME` body.
    pub fn decode(body: &[u8], limits: &Limits) -> Result<Self, MessageError> {
        Self::decode_fields(FieldMap::parse(body, limits)?, limits)
    }

    fn decode_fields(fields: FieldMap<'_>, limits: &Limits) -> Result<Self, MessageError> {
        let session_id = SessionId::from_le_bytes(required(
            fields.fixed::<16>(fid::F_SESSION_ID)?,
            fid::F_SESSION_ID,
        )?);
        Ok(Self {
            proto: ProtoVersion {
                major: required(fields.u16(fid::F_PROTO_MAJOR)?, fid::F_PROTO_MAJOR)?,
                minor: required(fields.u16(fid::F_PROTO_MINOR)?, fid::F_PROTO_MINOR)?,
            },
            caps: Caps::from_bits(required(fields.u32(fid::F_CAPS)?, fid::F_CAPS)?),
            epoch: required(fields.u64(fid::F_EPOCH)?, fid::F_EPOCH)?,
            current_seq: Seq(required(
                fields.u64(fid::F_CURRENT_SEQ)?,
                fid::F_CURRENT_SEQ,
            )?),
            client_id: ClientId::from_bytes(required(
                fields.fixed::<16>(fid::F_CLIENT_ID)?,
                fid::F_CLIENT_ID,
            )?),
            resync: ResyncMode::from_u8(required(fields.u8(fid::F_RESYNC)?, fid::F_RESYNC)?)?,
            limits: WelcomeLimits::decode(fields.require(fid::F_LIMITS)?, limits)?,
            server_time: required(fields.u64(fid::F_SERVER_TIME)?, fid::F_SERVER_TIME)?,
            server_nonce: required(
                fields.fixed::<32>(fid::F_SERVER_NONCE)?,
                fid::F_SERVER_NONCE,
            )?,
            session_id,
        })
    }

    /// Encode a plain `WELCOME` body without a server proof.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        self.encode_with_optional(None, None)
    }

    /// Encode a plain `WELCOME` body with `F_SERVER_PROOF` appended.
    ///
    /// The proof covers [`Welcome::proof_input`] of the same body without the
    /// proof field.
    pub fn encode_with_proof(
        &self,
        proof: &[u8; Self::SERVER_PROOF_LEN],
    ) -> Result<Vec<u8>, MessageError> {
        self.encode_with_optional(Some(proof), None)
    }

    /// Encode a plain `WELCOME` body with the server proof and the sealed
    /// `ACCEPT` appended.
    ///
    /// The proof covers both attachments because [`Welcome::proof_input`]
    /// excludes only `F_SERVER_PROOF`.
    pub fn encode_with_proof_and_accept(
        &self,
        proof: &[u8; Self::SERVER_PROOF_LEN],
        accept: &[u8; ACCEPT_SEALED_LEN],
    ) -> Result<Vec<u8>, MessageError> {
        self.encode_with_optional(Some(proof), Some(accept))
    }

    /// The canonical `WELCOME` bytes without `F_SERVER_PROOF`.
    ///
    /// This is the exact input to the server proof hash, on both sides.
    pub fn proof_input(body: &[u8], limits: &Limits) -> Result<[u8; 32], MessageError> {
        let fields = FieldMap::parse(body, limits)?;
        let canonical = fields.canonical_bytes_excluding(&[fid::F_SERVER_PROOF])?;
        Ok(*blake3::hash(&canonical).as_bytes())
    }

    /// Read `F_SERVER_PROOF` from an encoded body.
    pub fn server_proof(
        body: &[u8],
        limits: &Limits,
    ) -> Result<Option<[u8; Self::SERVER_PROOF_LEN]>, MessageError> {
        let fields = FieldMap::parse(body, limits)?;
        Ok(fields.fixed::<61>(fid::F_SERVER_PROOF)?)
    }

    /// Read the sealed `ACCEPT` from an encoded `WELCOME` body.
    pub fn sealed_accept(
        body: &[u8],
        limits: &Limits,
    ) -> Result<Option<[u8; ACCEPT_SEALED_LEN]>, MessageError> {
        let fields = FieldMap::parse(body, limits)?;
        Ok(fields.fixed::<ACCEPT_SEALED_LEN>(fid::F_SEALED_ACCEPT)?)
    }

    fn encode_with_optional(
        &self,
        proof: Option<&[u8; Self::SERVER_PROOF_LEN]>,
        accept: Option<&[u8; ACCEPT_SEALED_LEN]>,
    ) -> Result<Vec<u8>, MessageError> {
        let mut writer = WcpWriter::new();
        writer.u16(fid::F_PROTO_MAJOR, self.proto.major);
        writer.u16(fid::F_PROTO_MINOR, self.proto.minor);
        writer.u32(fid::F_CAPS, self.caps.bits());
        writer.u64(fid::F_EPOCH, self.epoch);
        writer.u64(fid::F_CURRENT_SEQ, self.current_seq.get());
        writer.bytes(fid::F_CLIENT_ID, &self.client_id.to_bytes());
        writer.u8(fid::F_RESYNC, self.resync.as_u8());
        writer.nested(fid::F_LIMITS, |nested| self.limits.write(nested));
        writer.u64(fid::F_SERVER_TIME, self.server_time);
        writer.bytes(fid::F_SERVER_NONCE, &self.server_nonce);
        writer.bytes(fid::F_SESSION_ID, &self.session_id.to_le_bytes());
        if let Some(proof) = proof {
            writer.bytes(fid::F_SERVER_PROOF, proof);
        }
        if let Some(accept) = accept {
            writer.bytes(fid::F_SEALED_ACCEPT, accept);
        }
        Ok(writer.finish()?)
    }
}

/// `AUTH` body: fixed 56-byte plaintext, sealed inside `HELLO`.
///
/// Layout:
///
/// ```text
/// client_nonce 32 | client_id 16 | proto_major 2 | proto_minor 2 | caps 4
/// ```
///
/// The client seals this before it sees `WELCOME`, so the body cannot name
/// the server nonce, session or epoch. It proves possession of the PSK and
/// commits to the identity and version the plaintext `HELLO` advertises.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Auth {
    /// Nonce the client sent in `HELLO`.
    pub client_nonce: [u8; 32],
    /// Client identity claimed in `HELLO`.
    pub client_id: ClientId,
    /// Protocol version the client offered in `HELLO`.
    pub proto: ProtoVersion,
    /// Capability set the client offered in `HELLO`.
    pub caps: Caps,
}

impl Auth {
    /// Plaintext width.
    pub const LEN: usize = 32 + 16 + 2 + 2 + 4;

    /// Encode the fixed layout.
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..32].copy_from_slice(&self.client_nonce);
        out[32..48].copy_from_slice(&self.client_id.to_bytes());
        out[48..50].copy_from_slice(&self.proto.major.to_le_bytes());
        out[50..52].copy_from_slice(&self.proto.minor.to_le_bytes());
        out[52..56].copy_from_slice(&self.caps.bits().to_le_bytes());
        out
    }

    /// Decode exactly [`Auth::LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`MessageError::BadBodyLen`] for any other width.
    pub fn decode(body: &[u8]) -> Result<Self, MessageError> {
        if body.len() != Self::LEN {
            return Err(MessageError::BadBodyLen {
                len: body.len(),
                need: Self::LEN,
            });
        }
        let mut client_nonce = [0u8; 32];
        client_nonce.copy_from_slice(&body[..32]);
        let mut client = [0u8; 16];
        client.copy_from_slice(&body[32..48]);
        Ok(Self {
            client_nonce,
            client_id: ClientId::from_bytes(client),
            proto: ProtoVersion {
                major: u16::from_le_bytes([body[48], body[49]]),
                minor: u16::from_le_bytes([body[50], body[51]]),
            },
            caps: Caps::from_bits(u32::from_le_bytes([
                body[52], body[53], body[54], body[55],
            ])),
        })
    }
}

/// `ACCEPT` body: fixed 32-byte plaintext, sealed inside `WELCOME`.
///
/// Layout: `epoch 8 | session_id 16 | current_seq 8`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Accept {
    /// Server epoch named by `WELCOME`.
    pub epoch: u64,
    /// Join session named by `WELCOME`.
    pub session_id: SessionId,
    /// Server sequence at acceptance time.
    pub current_seq: Seq,
}

impl Accept {
    /// Plaintext width.
    pub const LEN: usize = 8 + 16 + 8;

    /// Encode the fixed layout.
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..8].copy_from_slice(&self.epoch.to_le_bytes());
        out[8..24].copy_from_slice(&self.session_id.to_le_bytes());
        out[24..32].copy_from_slice(&self.current_seq.get().to_le_bytes());
        out
    }

    /// Decode exactly [`Accept::LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`MessageError::BadBodyLen`] for any other width.
    pub fn decode(body: &[u8]) -> Result<Self, MessageError> {
        if body.len() != Self::LEN {
            return Err(MessageError::BadBodyLen {
                len: body.len(),
                need: Self::LEN,
            });
        }
        let mut session = [0u8; 16];
        session.copy_from_slice(&body[8..24]);
        Ok(Self {
            epoch: u64::from_le_bytes([
                body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
            ]),
            session_id: SessionId::from_le_bytes(session),
            current_seq: Seq(u64::from_le_bytes([
                body[24], body[25], body[26], body[27], body[28], body[29], body[30], body[31],
            ])),
        })
    }
}

/// Relay sub-message kinds carried in `F_SUB_KIND` (44 §3.4).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum RelaySub {
    /// Snapshot-generation offer.
    Offer = 1,
    /// Grant of snapshot generation.
    Grant = 2,
    /// Snapshot request.
    SnapshotReq = 3,
    /// Diff request.
    DiffReq = 7,
    /// Block request.
    BlockReq = 8,
    /// Missing block notice.
    BlockMiss = 9,
    /// Cancel a sync session.
    Cancel = 10,
}

impl RelaySub {
    /// Decode a wire value. Unknown values are rejected, not coerced.
    pub fn from_u8(raw: u8) -> Result<Self, MessageError> {
        match raw {
            1 => Ok(Self::Offer),
            2 => Ok(Self::Grant),
            3 => Ok(Self::SnapshotReq),
            7 => Ok(Self::DiffReq),
            8 => Ok(Self::BlockReq),
            9 => Ok(Self::BlockMiss),
            10 => Ok(Self::Cancel),
            other => Err(MessageError::UnknownRelaySub(other)),
        }
    }

    /// Raw wire value.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Stable name for logs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Offer => "OFFER",
            Self::Grant => "GRANT",
            Self::SnapshotReq => "SNAPSHOT_REQ",
            Self::DiffReq => "DIFF_REQ",
            Self::BlockReq => "BLOCK_REQ",
            Self::BlockMiss => "BLOCK_MISS",
            Self::Cancel => "CANCEL",
        }
    }
}

/// Class-specific arguments of an `ORDERED` operation (44 §3.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpArgs<'a> {
    /// `WRITE`: whole-stream data reference.
    Write(DataRef),
    /// `PWRITE`: offset plus data reference.
    Pwrite {
        /// Write offset.
        offset: u64,
        /// Data reference.
        data: DataRef,
    },
    /// `TRUNCATE`: new length.
    Truncate {
        /// New length.
        length: u64,
    },
    /// `SETATTR`: optional mode and size change.
    Setattr {
        /// New mode, if any.
        mode: Option<u32>,
        /// New length, if this setattr also truncates.
        size: Option<u64>,
    },
    /// `RENAME`: destination path.
    Rename {
        /// Destination path.
        path2: WirePath<'a>,
    },
    /// `UNLINK`: no extra arguments.
    Unlink,
    /// `MKDIR`: mode.
    Mkdir {
        /// Directory mode.
        mode: u32,
    },
    /// `RMDIR`: no extra arguments.
    Rmdir,
    /// `LINK`: existing target path.
    Link {
        /// Existing inode path.
        target: WirePath<'a>,
    },
    /// `SYMLINK`: link contents, possibly relative.
    Symlink {
        /// Link contents.
        target: &'a str,
    },
    /// `CREATE_EXCL`: mode and open flags.
    CreateExcl {
        /// File mode.
        mode: u32,
        /// Open flags.
        flags: u32,
    },
    /// `FLOCK`: lock type and action.
    Flock {
        /// Lock type.
        lock_type: u8,
        /// Lock action.
        action: u8,
    },
    /// `FCNTL_LOCK`: lock type, action and range.
    FcntlLock {
        /// Lock type.
        lock_type: u8,
        /// Lock action.
        action: u8,
        /// Range start.
        start: u64,
        /// Range length.
        len: u64,
    },
    /// `SYNC_CTRL`: no extra arguments in v3.
    SyncCtrl,
    /// `LEAVE`: no extra arguments.
    Leave,
}

/// `ORDERED` body: sealed WCP (44 §3.2, 44 §3.4).
///
/// Every class carries `F_OP_ID`. The AEAD envelope authenticates the body;
/// there are no per-operation signature fields.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ordered<'a> {
    /// Author client.
    pub client_id: ClientId,
    /// Operation identifier.
    pub op_id: OpId,
    /// Operation class.
    pub op_class: OpClass,
    /// Path for file ops.
    pub path: Option<WirePath<'a>>,
    /// File attributes for file ops.
    pub attrs: Option<FileAttrs>,
    /// Class-specific arguments.
    pub args: OpArgs<'a>,
    /// The complete field map, including unknown fids.
    pub fields: FieldMap<'a>,
    raw: &'a [u8],
}

impl<'a> Ordered<'a> {
    /// Decode a sealed `ORDERED` body.
    pub fn decode(body: &'a [u8], limits: &Limits) -> Result<Self, MessageError> {
        let fields = FieldMap::parse(body, limits)?;
        let client_id = ClientId::from_bytes(required(
            fields.fixed::<16>(fid::F_CLIENT_ID)?,
            fid::F_CLIENT_ID,
        )?);
        let op_class = OpClass::from_u8(required(fields.u8(fid::F_OP_CLASS)?, fid::F_OP_CLASS)?)?;
        let op_id = OpId::from_bytes(required(fields.fixed::<16>(fid::F_OP_ID)?, fid::F_OP_ID)?);

        let (path, attrs) = if op_class.requires_file_attrs() {
            let path = path_field(&fields, fid::F_PATH, limits)?;
            let attrs = FileAttrs {
                mtime_ns: required(fields.u64(fid::F_MTIME_NS)?, fid::F_MTIME_NS)?,
                uid: required(fields.u32(fid::F_UID)?, fid::F_UID)?,
                gid: required(fields.u32(fid::F_GID)?, fid::F_GID)?,
            };
            (Some(path), Some(attrs))
        } else {
            (None, None)
        };

        let data = if matches!(op_class, OpClass::WRITE | OpClass::PWRITE) {
            Some(DataRef {
                session: SessionId::from_le_bytes(required(
                    fields.fixed::<16>(fid::F_DATA_SESSION)?,
                    fid::F_DATA_SESSION,
                )?),
                total_len: required(fields.u64(fid::F_TOTAL_LEN)?, fid::F_TOTAL_LEN)?,
                data_hash: required(fields.fixed::<32>(fid::F_DATA_HASH)?, fid::F_DATA_HASH)?,
            })
        } else {
            for probe in [fid::F_DATA_SESSION, fid::F_TOTAL_LEN, fid::F_DATA_HASH] {
                if fields.get(probe).is_some() {
                    return Err(MessageError::BadValue {
                        fid: probe,
                        reason: "data fields are only valid on WRITE and PWRITE",
                    });
                }
            }
            None
        };

        let args = match op_class {
            OpClass::WRITE => OpArgs::Write(required(data, fid::F_DATA_SESSION)?),
            OpClass::PWRITE => OpArgs::Pwrite {
                offset: required(fields.u64(fid::F_OFFSET)?, fid::F_OFFSET)?,
                data: required(data, fid::F_DATA_SESSION)?,
            },
            OpClass::TRUNCATE => OpArgs::Truncate {
                length: required(fields.u64(fid::F_LENGTH)?, fid::F_LENGTH)?,
            },
            OpClass::SETATTR => OpArgs::Setattr {
                mode: fields.u32(fid::F_MODE)?,
                size: fields.u64(fid::F_LENGTH)?,
            },
            OpClass::RENAME => OpArgs::Rename {
                path2: path_field(&fields, fid::F_PATH2, limits)?,
            },
            OpClass::UNLINK => OpArgs::Unlink,
            OpClass::MKDIR => OpArgs::Mkdir {
                mode: required(fields.u32(fid::F_MODE)?, fid::F_MODE)?,
            },
            OpClass::RMDIR => OpArgs::Rmdir,
            OpClass::LINK => OpArgs::Link {
                target: path_field(&fields, fid::F_TARGET, limits)?,
            },
            OpClass::SYMLINK => {
                let target = required(fields.str(fid::F_TARGET)?, fid::F_TARGET)?;
                if target.len() > usize::from(limits.path_max) {
                    return Err(MessageError::Path(PathError::TooLong {
                        len: target.len(),
                        max: usize::from(limits.path_max),
                    }));
                }
                OpArgs::Symlink { target }
            }
            OpClass::CREATE_EXCL => OpArgs::CreateExcl {
                mode: required(fields.u32(fid::F_MODE)?, fid::F_MODE)?,
                flags: required(fields.u32(fid::F_OP_FLAGS)?, fid::F_OP_FLAGS)?,
            },
            OpClass::FLOCK => OpArgs::Flock {
                lock_type: required(fields.u8(fid::F_LOCK_TYPE)?, fid::F_LOCK_TYPE)?,
                action: required(fields.u8(fid::F_LOCK_ACTION)?, fid::F_LOCK_ACTION)?,
            },
            OpClass::FCNTL_LOCK => OpArgs::FcntlLock {
                lock_type: required(fields.u8(fid::F_LOCK_TYPE)?, fid::F_LOCK_TYPE)?,
                action: required(fields.u8(fid::F_LOCK_ACTION)?, fid::F_LOCK_ACTION)?,
                start: required(fields.u64(fid::F_LOCK_START)?, fid::F_LOCK_START)?,
                len: required(fields.u64(fid::F_LOCK_LEN)?, fid::F_LOCK_LEN)?,
            },
            OpClass::SYNC_CTRL => OpArgs::SyncCtrl,
            OpClass::LEAVE => OpArgs::Leave,
            other => return Err(MessageError::UnknownOpClass(other.get())),
        };

        Ok(Self {
            client_id,
            op_id,
            op_class,
            path,
            attrs,
            args,
            fields,
            raw: body,
        })
    }

    /// The original body bytes, byte-exact.
    ///
    /// The server rebroadcasts `ORDERED` without re-encoding, so this is the
    /// only encoder that must not normalize (44 §2.4, INV-17).
    pub fn encode_body(&self) -> Vec<u8> {
        self.raw.to_vec()
    }

    /// Canonical bytes with `exclude` removed (44 §4.6, INV-24).
    pub fn canonical_bytes_excluding(&self, exclude: &[u8]) -> Result<Vec<u8>, WcpError> {
        self.fields.canonical_bytes_excluding(exclude)
    }

    /// The path as text, if this class has one.
    pub fn path_str(&self) -> Option<&'a str> {
        self.path.map(|path| path.as_str())
    }

    /// The data reference, if this is `WRITE` or `PWRITE`.
    pub fn data(&self) -> Option<DataRef> {
        match &self.args {
            OpArgs::Write(data) => Some(*data),
            OpArgs::Pwrite { data, .. } => Some(*data),
            _ => None,
        }
    }

}

impl fmt::Debug for Ordered<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ordered")
            .field("client_id", &self.client_id)
            .field("op_id", &self.op_id)
            .field("op_class", &self.op_class)
            .field("path", &self.path)
            .field("attrs", &self.attrs)
            .field("args", &self.args)
            .field("fields", &self.fields)
            .finish()
    }
}

/// `RESPONSE` body: sealed generic WCP.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Response<'a> {
    /// Complete field map.
    pub fields: FieldMap<'a>,
}

impl<'a> Response<'a> {
    /// Decode a sealed `RESPONSE` body.
    pub fn decode(body: &'a [u8], limits: &Limits) -> Result<Self, MessageError> {
        Ok(Self {
            fields: FieldMap::parse(body, limits)?,
        })
    }

    /// Encode a canonical `RESPONSE` body.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        Ok(self.fields.canonical_bytes_excluding(&[])?)
    }
}

/// `RELAY` body: sealed WCP with a sub-kind (44 §3.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Relay<'a> {
    /// Sub-message kind.
    pub sub: RelaySub,
    /// Complete field map, including `F_SUB_KIND` and unknown fids.
    pub fields: FieldMap<'a>,
}

impl<'a> Relay<'a> {
    /// Decode a sealed `RELAY` body.
    pub fn decode(body: &'a [u8], limits: &Limits) -> Result<Self, MessageError> {
        let fields = FieldMap::parse(body, limits)?;
        let sub = RelaySub::from_u8(required(fields.u8(fid::F_SUB_KIND)?, fid::F_SUB_KIND)?)?;
        Ok(Self { sub, fields })
    }

    /// Encode a canonical `RELAY` body.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        Ok(self.fields.canonical_bytes_excluding(&[])?)
    }
}

/// `ACK` body: sealed WCP carrying concatenated op ids (44 §3.4).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ack<'a> {
    /// Concatenated 16-byte op ids.
    pub op_ids: &'a [u8],
}

impl<'a> Ack<'a> {
    /// Decode a sealed `ACK` body.
    pub fn decode(body: &'a [u8], limits: &Limits) -> Result<Self, MessageError> {
        let fields = FieldMap::parse(body, limits)?;
        let op_ids = fields.require(fid::F_OP_IDS)?;
        if op_ids.len() % OpId::LEN != 0 {
            return Err(MessageError::BadOpIdsLen(op_ids.len()));
        }
        Ok(Self { op_ids })
    }

    /// Encode an `ACK` body.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        let mut writer = WcpWriter::new();
        writer.bytes(fid::F_OP_IDS, self.op_ids);
        Ok(writer.finish()?)
    }

    /// Iterate the acknowledged ids.
    pub fn iter(&self) -> impl Iterator<Item = OpId> + '_ {
        self.op_ids.chunks_exact(OpId::LEN).map(|chunk| {
            let mut bytes = [0u8; OpId::LEN];
            bytes.copy_from_slice(chunk);
            OpId::from_bytes(bytes)
        })
    }
}

impl fmt::Debug for Ack<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ack({} op ids)", self.op_ids.len() / OpId::LEN)
    }
}

/// `PING` body: sealed WCP (44 §3.4).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Ping {
    /// Client clock.
    pub client_time: u64,
}

impl Ping {
    /// Decode a sealed `PING` body.
    pub fn decode(body: &[u8], limits: &Limits) -> Result<Self, MessageError> {
        let fields = FieldMap::parse(body, limits)?;
        Ok(Self {
            client_time: required(fields.u64(fid::F_CLIENT_TIME)?, fid::F_CLIENT_TIME)?,
        })
    }

    /// Encode a `PING` body.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        let mut writer = WcpWriter::new();
        writer.u64(fid::F_CLIENT_TIME, self.client_time);
        Ok(writer.finish()?)
    }
}

/// `PONG` body: plain WCP (44 §3.4).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Pong {
    /// Server clock.
    pub server_time: u64,
}

impl Pong {
    /// Decode a plain `PONG` body.
    pub fn decode(body: &[u8], limits: &Limits) -> Result<Self, MessageError> {
        let fields = FieldMap::parse(body, limits)?;
        Ok(Self {
            server_time: required(fields.u64(fid::F_SERVER_TIME)?, fid::F_SERVER_TIME)?,
        })
    }

    /// Encode a `PONG` body.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        let mut writer = WcpWriter::new();
        writer.u64(fid::F_SERVER_TIME, self.server_time);
        Ok(writer.finish()?)
    }
}

/// `ERROR` body: plain WCP (44 §3.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Error<'a> {
    /// Transport reason.
    pub reason: TrnReason,
    /// Detail bytes, at most `limits.detail_max`.
    pub detail: &'a [u8],
    /// Related session, if any.
    pub session_id: Option<SessionId>,
}

impl<'a> Error<'a> {
    /// Decode a plain `ERROR` body.
    pub fn decode(body: &'a [u8], limits: &Limits) -> Result<Self, MessageError> {
        let fields = FieldMap::parse(body, limits)?;
        let reason_raw = required(fields.u16(fid::F_TRN_REASON)?, fid::F_TRN_REASON)?;
        let reason =
            TrnReason::from_u16(reason_raw).ok_or(MessageError::UnknownTrnReason(reason_raw))?;
        let detail = fields.get(fid::F_DETAIL).unwrap_or(&[]);
        let detail_max = usize::from(limits.detail_max);
        if detail.len() > detail_max {
            return Err(MessageError::Wcp(WcpError::FieldTooLong {
                fid: fid::F_DETAIL,
                len: detail.len(),
                max: detail_max,
            }));
        }
        let session_id = fields
            .fixed::<16>(fid::F_SESSION_ID)?
            .map(SessionId::from_le_bytes);
        Ok(Self {
            reason,
            detail,
            session_id,
        })
    }

    /// Encode an `ERROR` body.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        let mut writer = WcpWriter::new();
        writer.u16(fid::F_TRN_REASON, self.reason.as_u16());
        writer.bytes(fid::F_DETAIL, self.detail);
        if let Some(session_id) = self.session_id {
            writer.bytes(fid::F_SESSION_ID, &session_id.to_le_bytes());
        }
        Ok(writer.finish()?)
    }
}

/// `KICK` body: plain WCP (44 §3.4).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Kick {
    /// Kick reason.
    pub reason: KickReason,
}

impl Kick {
    /// Decode a plain `KICK` body.
    pub fn decode(body: &[u8], limits: &Limits) -> Result<Self, MessageError> {
        let fields = FieldMap::parse(body, limits)?;
        let raw = required(fields.u16(fid::F_KICK_REASON)?, fid::F_KICK_REASON)?;
        let reason = KickReason::from_u16(raw).ok_or(MessageError::UnknownKickReason(raw))?;
        Ok(Self { reason })
    }

    /// Encode a `KICK` body.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        let mut writer = WcpWriter::new();
        writer.u16(fid::F_KICK_REASON, self.reason.as_u16());
        Ok(writer.finish()?)
    }
}

/// `FLOW` body: plain WCP (44 §3.4, 44 §5.4).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Flow {
    /// Additional credit in bytes.
    pub grant_bytes: u32,
}

impl Flow {
    /// Decode a plain `FLOW` body.
    pub fn decode(body: &[u8], limits: &Limits) -> Result<Self, MessageError> {
        let fields = FieldMap::parse(body, limits)?;
        Ok(Self {
            grant_bytes: required(fields.u32(fid::F_GRANT_BYTES)?, fid::F_GRANT_BYTES)?,
        })
    }

    /// Encode a `FLOW` body.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        let mut writer = WcpWriter::new();
        writer.u32(fid::F_GRANT_BYTES, self.grant_bytes);
        Ok(writer.finish()?)
    }
}

/// `SYNC_END` body: plain WCP (44 §3.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SyncEnd<'a> {
    /// End reason.
    pub reason: SyncEndReason,
    /// Optional detail bytes.
    pub detail: Option<&'a [u8]>,
}

impl<'a> SyncEnd<'a> {
    /// Decode a plain `SYNC_END` body.
    pub fn decode(body: &'a [u8], limits: &Limits) -> Result<Self, MessageError> {
        let fields = FieldMap::parse(body, limits)?;
        let raw = required(fields.u8(fid::F_SYNC_REASON)?, fid::F_SYNC_REASON)?;
        let reason = SyncEndReason::from_u8(raw).ok_or(MessageError::UnknownSyncReason(raw))?;
        let detail = fields.get(fid::F_DETAIL);
        if let Some(detail) = detail {
            let detail_max = usize::from(limits.detail_max);
            if detail.len() > detail_max {
                return Err(MessageError::Wcp(WcpError::FieldTooLong {
                    fid: fid::F_DETAIL,
                    len: detail.len(),
                    max: detail_max,
                }));
            }
        }
        Ok(Self { reason, detail })
    }

    /// Encode a `SYNC_END` body.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        let mut writer = WcpWriter::new();
        writer.u8(fid::F_SYNC_REASON, self.reason.as_u8());
        if let Some(detail) = self.detail {
            writer.bytes(fid::F_DETAIL, detail);
        }
        Ok(writer.finish()?)
    }
}

/// `LEAVE` (0x1B) body: plain, unsigned server notice (44 §3.4, 44 D4).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Leave {
    /// Client that left.
    pub client_id: ClientId,
    /// Reason byte.
    pub reason: u8,
    /// Last signed sequence the server saw.
    pub last_signed_seq: u64,
}

impl Leave {
    /// Decode a plain `LEAVE` body.
    pub fn decode(body: &[u8], limits: &Limits) -> Result<Self, MessageError> {
        let fields = FieldMap::parse(body, limits)?;
        Ok(Self {
            client_id: ClientId::from_bytes(required(
                fields.fixed::<16>(fid::F_CLIENT_ID)?,
                fid::F_CLIENT_ID,
            )?),
            reason: required(fields.u8(fid::F_LEAVE_REASON)?, fid::F_LEAVE_REASON)?,
            last_signed_seq: required(fields.u64(fid::F_LAST_SIGNED_SEQ)?, fid::F_LAST_SIGNED_SEQ)?,
        })
    }

    /// Encode a `LEAVE` body.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        let mut writer = WcpWriter::new();
        writer.bytes(fid::F_CLIENT_ID, &self.client_id.to_bytes());
        writer.u8(fid::F_LEAVE_REASON, self.reason);
        writer.u64(fid::F_LAST_SIGNED_SEQ, self.last_signed_seq);
        Ok(writer.finish()?)
    }
}

/// `STREAM_DATA` payload: raw sealed bytes, never WCP (44 §3.1).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StreamData<'a> {
    /// Raw body bytes.
    pub data: &'a [u8],
}

impl fmt::Debug for StreamData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StreamData({} bytes)", self.data.len())
    }
}

/// One decoded message body.
///
/// The variant names mirror [`MsgType`] so the table can be checked
/// exhaustively. `Ordered` holds a [`FieldMap`] with a fixed 64-slot array;
/// the enum is therefore large but never allocates.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug)]
pub enum Message<'a> {
    /// `HELLO` (0x01).
    Hello(Hello),
    /// `WELCOME` (0x02).
    Welcome(Welcome),
    /// `ORDERED` (0x10).
    Ordered(Ordered<'a>),
    /// `RESPONSE` (0x11).
    Response(Response<'a>),
    /// `RELAY` (0x12).
    Relay(Relay<'a>),
    /// `ACK` (0x13).
    Ack(Ack<'a>),
    /// `PING` (0x14).
    Ping(Ping),
    /// `PONG` (0x15).
    Pong(Pong),
    /// `ERROR` (0x16).
    Error(Error<'a>),
    /// `KICK` (0x17).
    Kick(Kick),
    /// `FLOW` (0x18).
    Flow(Flow),
    /// `SYNC_END` (0x19).
    SyncEnd(SyncEnd<'a>),
    /// `STREAM_DATA` (0x1A), raw.
    StreamData(StreamData<'a>),
    /// `LEAVE` (0x1B).
    Leave(Leave),
}

impl Message<'_> {
    /// The wire type of this variant.
    pub fn msg_type(&self) -> MsgType {
        match self {
            Self::Hello(_) => MsgType::HELLO,
            Self::Welcome(_) => MsgType::WELCOME,
            Self::Ordered(_) => MsgType::ORDERED,
            Self::Response(_) => MsgType::RESPONSE,
            Self::Relay(_) => MsgType::RELAY,
            Self::Ack(_) => MsgType::ACK,
            Self::Ping(_) => MsgType::PING,
            Self::Pong(_) => MsgType::PONG,
            Self::Error(_) => MsgType::ERROR,
            Self::Kick(_) => MsgType::KICK,
            Self::Flow(_) => MsgType::FLOW,
            Self::SyncEnd(_) => MsgType::SYNC_END,
            Self::StreamData(_) => MsgType::STREAM_DATA,
            Self::Leave(_) => MsgType::LEAVE,
        }
    }

    /// The body encoding this type requires (44 §3.1).
    pub fn body_encoding(&self) -> BodyEncoding {
        self.msg_type().body_encoding()
    }

    /// The prefix this type requires (44 §2.1).
    pub fn prefix_kind(&self) -> PrefixKind {
        self.msg_type().prefix_kind()
    }

    /// Encode the body. `ORDERED` is byte-exact; other bodies are canonical.
    pub fn encode_body(&self) -> Result<Vec<u8>, MessageError> {
        match self {
            Self::Hello(message) => message.encode(),
            Self::Welcome(message) => message.encode(),
            Self::Ordered(message) => Ok(message.encode_body()),
            Self::Response(message) => message.encode(),
            Self::Relay(message) => message.encode(),
            Self::Ack(message) => message.encode(),
            Self::Ping(message) => message.encode(),
            Self::Pong(message) => message.encode(),
            Self::Error(message) => message.encode(),
            Self::Kick(message) => message.encode(),
            Self::Flow(message) => message.encode(),
            Self::SyncEnd(message) => message.encode(),
            Self::StreamData(message) => Ok(message.data.to_vec()),
            Self::Leave(message) => message.encode(),
        }
    }

    /// Encode a plaintext body, rejecting sealed types (44 §3.1).
    pub fn encode_plain(&self) -> Result<Vec<u8>, MessageError> {
        if self.body_encoding() != BodyEncoding::Plain {
            return Err(MessageError::WrongEncoding(self.msg_type()));
        }
        self.encode_body()
    }

    /// Encode a sealed body, rejecting plain types.
    ///
    /// `STREAM_DATA` is raw and passes through unchanged; it is not WCP.
    pub fn encode_sealed(&self) -> Result<Vec<u8>, MessageError> {
        if let Self::StreamData(message) = self {
            return Ok(message.data.to_vec());
        }
        if self.body_encoding() != BodyEncoding::Sealed {
            return Err(MessageError::WrongEncoding(self.msg_type()));
        }
        self.encode_body()
    }
}

/// Read the protocol version a plain `HELLO` or `WELCOME` announces.
///
/// Only the two version fields are read. This lets a decoder reject an older
/// wire format as a version mismatch before it requires fields that older
/// format does not carry, such as the sealed `AUTH`.
pub fn peek_proto(body: &[u8], limits: &Limits) -> Result<ProtoVersion, MessageError> {
    proto_from_fields(FieldMap::parse(body, limits)?)
}

fn proto_from_fields(fields: FieldMap<'_>) -> Result<ProtoVersion, MessageError> {
    Ok(ProtoVersion {
        major: required(fields.u16(fid::F_PROTO_MAJOR)?, fid::F_PROTO_MAJOR)?,
        minor: required(fields.u16(fid::F_PROTO_MINOR)?, fid::F_PROTO_MINOR)?,
    })
}

fn check_proto_major(fields: FieldMap<'_>) -> Result<(), MessageError> {
    let remote = proto_from_fields(fields)?;
    if remote.major == ProtoVersion::CURRENT.major {
        Ok(())
    } else {
        Err(MessageError::ProtocolVersion {
            local: ProtoVersion::CURRENT.major,
            remote: remote.major,
        })
    }
}

/// Decode a plaintext body. Only the plain types in 44 §3.1 are accepted.
///
/// `HELLO` and `WELCOME` are version-checked first: a peer that announces an
/// older major is rejected with [`MessageError::ProtocolVersion`] instead of
/// failing on a field this build added.
pub fn decode_plain<'a>(
    msg_type: MsgType,
    body: &'a [u8],
    limits: &Limits,
) -> Result<Message<'a>, MessageError> {
    match msg_type {
        MsgType::HELLO => {
            let fields = FieldMap::parse(body, limits)?;
            check_proto_major(fields)?;
            Ok(Message::Hello(Hello::decode_fields(fields)?))
        }
        MsgType::WELCOME => {
            let fields = FieldMap::parse(body, limits)?;
            check_proto_major(fields)?;
            Ok(Message::Welcome(Welcome::decode_fields(fields, limits)?))
        }
        MsgType::ERROR => Ok(Message::Error(Error::decode(body, limits)?)),
        other => Err(MessageError::WrongEncoding(other)),
    }
}

/// Decode a sealed body. Only the sealed types in 44 §3.1 are accepted.
///
/// `STREAM_DATA` is raw and is handled by the fragment layer; it is rejected
/// here (44 §3.1). No signature verification happens at this layer (INV-23
/// verification belongs to W4).
pub fn decode_sealed<'a>(
    msg_type: MsgType,
    body: &'a [u8],
    limits: &Limits,
) -> Result<Message<'a>, MessageError> {
    match msg_type {
        MsgType::ORDERED => Ok(Message::Ordered(Ordered::decode(body, limits)?)),
        MsgType::RESPONSE => Ok(Message::Response(Response::decode(body, limits)?)),
        MsgType::RELAY => Ok(Message::Relay(Relay::decode(body, limits)?)),
        MsgType::ACK => Ok(Message::Ack(Ack::decode(body, limits)?)),
        MsgType::PING => Ok(Message::Ping(Ping::decode(body, limits)?)),
        MsgType::PONG => Ok(Message::Pong(Pong::decode(body, limits)?)),
        MsgType::KICK => Ok(Message::Kick(Kick::decode(body, limits)?)),
        MsgType::FLOW => Ok(Message::Flow(Flow::decode(body, limits)?)),
        MsgType::SYNC_END => Ok(Message::SyncEnd(SyncEnd::decode(body, limits)?)),
        MsgType::LEAVE => Ok(Message::Leave(Leave::decode(body, limits)?)),
        other => Err(MessageError::WrongEncoding(other)),
    }
}

/// Default replay table size: one million op ids (44 V12).
pub const DEFAULT_OP_ID_CAPACITY: usize = 1 << 20;

/// A replay verdict for one `op_id`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpIdVerdict {
    /// First observation.
    Fresh,
    /// Seen before with the same or a larger sequence.
    Duplicate,
    /// Seen before with a larger sequence; the minimum was lowered.
    Earlier,
}

/// Bounded replay table: `op_id -> minimum observed seq` (44 V12, INV-12).
///
/// The minimum sequence wins because a server may rebroadcast the same
/// signed op at several positions; only the earliest is authoritative.
pub struct OpIdLog {
    seen: HashMap<OpId, Seq>,
    order: VecDeque<OpId>,
    capacity: usize,
}

impl Default for OpIdLog {
    fn default() -> Self {
        Self::new(DEFAULT_OP_ID_CAPACITY)
    }
}

impl OpIdLog {
    /// Create a log holding at most `capacity` ids. Zero is rounded up to 1.
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: HashMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    /// Record an observation and return the replay verdict.
    pub fn observe(&mut self, op_id: OpId, seq: Seq) -> OpIdVerdict {
        if let Some(existing) = self.seen.get_mut(&op_id) {
            if seq.get() >= existing.get() {
                return OpIdVerdict::Duplicate;
            }
            *existing = seq;
            return OpIdVerdict::Earlier;
        }
        self.seen.insert(op_id, seq);
        self.order.push_back(op_id);
        if self.order.len() > self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.seen.remove(&evicted);
            }
        }
        OpIdVerdict::Fresh
    }

    /// Minimum sequence recorded for `op_id`.
    pub fn get(&self, op_id: OpId) -> Option<Seq> {
        self.seen.get(&op_id).copied()
    }

    /// Number of tracked ids.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Configured capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl fmt::Debug for OpIdLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpIdLog")
            .field("len", &self.seen.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

/// A sequencing verdict for one incoming `seq`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SeqVerdict {
    /// Exactly the next sequence.
    Next,
    /// Already seen.
    Duplicate,
    /// A hole: `expected` has not arrived.
    Gap {
        /// The sequence that should arrive next.
        expected: u64,
    },
    /// `seq == 0`, which is never sequenced.
    Unsequenced,
}

/// Strict in-order gate for downlink sequences (44 INV-05).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SeqGate {
    next: u64,
}

impl SeqGate {
    /// Start at `Seq::FIRST` (1).
    pub fn new() -> Self {
        Self {
            next: Seq::FIRST.get(),
        }
    }

    /// Classify an arriving sequence. Gaps do not advance the gate.
    pub fn observe(&mut self, seq: Seq) -> SeqVerdict {
        let raw = seq.get();
        if raw == Seq::UNSEQUENCED.get() {
            return SeqVerdict::Unsequenced;
        }
        if raw == self.next {
            self.next = self.next.saturating_add(1);
            return SeqVerdict::Next;
        }
        if raw < self.next {
            return SeqVerdict::Duplicate;
        }
        SeqVerdict::Gap {
            expected: self.next,
        }
    }

    /// The next expected sequence.
    pub fn next(&self) -> Seq {
        Seq(self.next)
    }
}

impl Default for SeqGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::collections::HashSet;

    use proptest::prelude::*;

    use super::*;
    use crate::protocol::version::{VersionError, negotiate};

    fn limits() -> Limits {
        Limits::default()
    }

    fn welcome_fixture() -> Welcome {
        Welcome {
            proto: ProtoVersion::CURRENT,
            caps: Caps::REQUIRED,
            epoch: 9,
            current_seq: Seq(42),
            client_id: ClientId::from_bytes([0x11; 16]),
            resync: ResyncMode::None,
            limits: WelcomeLimits {
                max_frame: 131_072,
                credit_bytes: 1 << 20,
                session_ttl_s: 60,
                max_sessions: 8,
            },
            server_time: 1_234,
            server_nonce: [0x22; 32],
            session_id: SessionId(0x33),
        }
    }

    #[test]
    fn welcome_proof_roundtrips_and_is_excluded_from_its_input() {
        let welcome = welcome_fixture();
        let plain = welcome.encode().unwrap();
        let proof = [0x5e; Welcome::SERVER_PROOF_LEN];
        let accept = [0x5c; ACCEPT_SEALED_LEN];
        let body = welcome.encode_with_proof_and_accept(&proof, &accept).unwrap();

        assert_eq!(
            Welcome::server_proof(&body, &limits()).unwrap(),
            Some(proof)
        );
        assert_eq!(
            Welcome::sealed_accept(&body, &limits()).unwrap(),
            Some(accept)
        );
        assert_eq!(
            Welcome::proof_input(&body, &limits()).unwrap(),
            *blake3::hash(
                &rebuilt(&plain, &[(fid::F_SEALED_ACCEPT, accept.to_vec())], &[])
            )
            .as_bytes()
        );
        assert_eq!(Welcome::decode(&body, &limits()).unwrap(), welcome);

        let without = welcome.encode().unwrap();
        assert_eq!(Welcome::server_proof(&without, &limits()).unwrap(), None);
        assert_eq!(Welcome::sealed_accept(&without, &limits()).unwrap(), None);
        assert_eq!(
            Welcome::proof_input(&without, &limits()).unwrap(),
            *blake3::hash(&without).as_bytes()
        );
    }

    #[test]
    fn auth_layout_is_frozen() {
        let auth = Auth {
            client_nonce: [0x11; 32],
            client_id: ClientId::from_bytes([0x55; 16]),
            proto: ProtoVersion { major: 3, minor: 7 },
            caps: Caps::REQUIRED,
        };
        let bytes = auth.encode();
        assert_eq!(bytes.len(), 56);
        assert_eq!(&bytes[..32], &[0x11; 32]);
        assert_eq!(&bytes[32..48], &[0x55; 16]);
        assert_eq!(&bytes[48..50], &3u16.to_le_bytes());
        assert_eq!(&bytes[50..52], &7u16.to_le_bytes());
        assert_eq!(&bytes[52..56], &Caps::REQUIRED.bits().to_le_bytes());
        assert_eq!(Auth::decode(&bytes).unwrap(), auth);
        assert_eq!(
            Auth::decode(&bytes[..55]).unwrap_err(),
            MessageError::BadBodyLen {
                len: 55,
                need: 56
            }
        );
        assert_eq!(
            Auth::decode(&[0u8; 57]).unwrap_err(),
            MessageError::BadBodyLen {
                len: 57,
                need: 56
            }
        );
    }

    #[test]
    fn accept_layout_is_frozen() {
        let accept = Accept {
            epoch: 0x44,
            session_id: SessionId(0x33),
            current_seq: Seq(0x55),
        };
        let bytes = accept.encode();
        assert_eq!(bytes.len(), 32);
        assert_eq!(&bytes[..8], &0x44u64.to_le_bytes());
        assert_eq!(&bytes[8..24], &SessionId(0x33).to_le_bytes());
        assert_eq!(&bytes[24..32], &0x55u64.to_le_bytes());
        assert_eq!(Accept::decode(&bytes).unwrap(), accept);
        assert_eq!(
            Accept::decode(&bytes[..31]).unwrap_err(),
            MessageError::BadBodyLen { len: 31, need: 32 }
        );
    }

    #[test]
    fn plain_decoder_accepts_only_pre_key_frames() {
        for msg_type in [
            MsgType::PONG,
            MsgType::KICK,
            MsgType::FLOW,
            MsgType::SYNC_END,
            MsgType::LEAVE,
            MsgType::ORDERED,
            MsgType::PING,
        ] {
            assert_eq!(
                decode_plain(msg_type, &[], &limits()).unwrap_err(),
                MessageError::WrongEncoding(msg_type)
            );
        }
        for msg_type in [MsgType::HELLO, MsgType::WELCOME, MsgType::ERROR] {
            assert_eq!(
                decode_sealed(msg_type, &[], &limits()).unwrap_err(),
                MessageError::WrongEncoding(msg_type)
            );
        }
    }

    fn field_bytes(field_id: u8, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + value.len());
        out.push(field_id);
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(value);
        out
    }

    fn rebuilt(body: &[u8], add: &[(u8, Vec<u8>)], drop: &[u8]) -> Vec<u8> {
        let map = FieldMap::parse(body, &limits()).unwrap();
        let mut writer = WcpWriter::new();
        for (field_id, value) in map.iter() {
            if field_id == fid::F_WCP_VER || drop.contains(&field_id) {
                continue;
            }
            writer.bytes(field_id, value);
        }
        for (field_id, value) in add {
            writer.bytes(*field_id, value);
        }
        writer.finish().unwrap()
    }

    fn ordered_common(writer: &mut WcpWriter, class: OpClass) {
        writer.bytes(fid::F_CLIENT_ID, &[1u8; 16]);
        writer.bytes(fid::F_OP_ID, &[2u8; 16]);
        writer.u8(fid::F_OP_CLASS, class.get());
    }

    fn ordered_write_body() -> Vec<u8> {
        let mut writer = WcpWriter::new();
        ordered_common(&mut writer, OpClass::WRITE);
        writer.str(fid::F_PATH, "/dir/file");
        writer.u64(fid::F_MTIME_NS, 1_700_000_000_000_000_000);
        writer.u32(fid::F_UID, 1000);
        writer.u32(fid::F_GID, 1000);
        writer.bytes(fid::F_DATA_SESSION, &[5u8; 16]);
        writer.u64(fid::F_TOTAL_LEN, 4096);
        writer.bytes(fid::F_DATA_HASH, &[6u8; 32]);
        writer.finish().unwrap()
    }

    fn ordered_pwrite_body() -> Vec<u8> {
        let mut writer = WcpWriter::new();
        ordered_common(&mut writer, OpClass::PWRITE);
        writer.str(fid::F_PATH, "/dir/file");
        writer.u64(fid::F_MTIME_NS, 1_700_000_000_000_000_000);
        writer.u32(fid::F_UID, 1000);
        writer.u32(fid::F_GID, 1000);
        writer.bytes(fid::F_DATA_SESSION, &[5u8; 16]);
        writer.u64(fid::F_TOTAL_LEN, 4096);
        writer.bytes(fid::F_DATA_HASH, &[6u8; 32]);
        writer.u64(fid::F_OFFSET, 512);
        writer.finish().unwrap()
    }

    fn ordered_leave_body() -> Vec<u8> {
        let mut writer = WcpWriter::new();
        ordered_common(&mut writer, OpClass::LEAVE);
        writer.finish().unwrap()
    }

    /// 44:V5 / 44 §3.3 -- WCP roundtrip, sorted canonical form, unknown fid.
    #[test]
    fn u_messages_wcp_roundtrip() {
        let limits = limits();
        let mut writer = WcpWriter::new();
        writer.u8(0x10, 7);
        writer.u16(0x11, 0x1234);
        writer.u32(0x12, 0xdead_beef);
        writer.u64(0x13, 0x0102_0304_0506_0708);
        writer.bytes(0x14, b"raw");
        writer.str(0x15, "hello");
        writer.bytes(0x7E, b"unknown");
        writer.nested(fid::F_LIMITS, |nested| {
            nested.u32(fid::F_LIMIT_MAX_FRAME, 1024);
            nested.u32(fid::F_LIMIT_CREDIT_BYTES, 2048);
            nested.u32(fid::F_LIMIT_SESSION_TTL_S, 60);
            nested.u32(fid::F_LIMIT_MAX_SESSIONS, 32);
        });
        let body = writer.finish().unwrap();
        let map = FieldMap::parse(&body, &limits).unwrap();

        assert_eq!(map.u8(0x10).unwrap(), Some(7));
        assert_eq!(map.u16(0x11).unwrap(), Some(0x1234));
        assert_eq!(map.u32(0x12).unwrap(), Some(0xdead_beef));
        assert_eq!(map.u64(0x13).unwrap(), Some(0x0102_0304_0506_0708));
        assert_eq!(map.get(0x14), Some(b"raw".as_slice()));
        assert_eq!(map.str(0x15).unwrap(), Some("hello"));
        assert_eq!(map.get(0x7E), Some(b"unknown".as_slice()));
        assert_eq!(map.version(), WcpVer::CURRENT);
        assert_eq!(map.as_bytes(), body.as_slice());

        let nested_body = map.require(fid::F_LIMITS).unwrap();
        let nested = FieldMap::parse(nested_body, &limits).unwrap();
        assert_eq!(nested.u32(fid::F_LIMIT_MAX_FRAME).unwrap(), Some(1024));
        assert_eq!(nested.u32(fid::F_LIMIT_MAX_SESSIONS).unwrap(), Some(32));

        let mut previous = 0u8;
        for (field_id, _) in map.iter() {
            assert!(field_id > previous, "fields are sorted by fid");
            previous = field_id;
        }
        assert_eq!(map.canonical_bytes_excluding(&[]).unwrap(), body);
        assert!(!format!("{map:?}").contains("hello"));

        let big = vec![0u8; usize::from(u16::MAX) + 1];
        let mut oversized = WcpWriter::new();
        oversized.bytes(0x20, &big);
        assert_eq!(
            oversized.finish().unwrap_err(),
            WcpError::FieldTooLong {
                fid: 0x20,
                len: usize::from(u16::MAX) + 1,
                max: usize::from(u16::MAX),
            }
        );

        let mut too_big = WcpWriter::new();
        for index in 0..63u8 {
            too_big.bytes(0x20 + index, &[0u8; 1040]);
        }
        assert!(matches!(too_big.finish(), Err(WcpError::TooLarge { .. })));
    }

    /// 44:R7 / 44 §3.3 -- duplicate fids and incompatible versions are rejected.
    #[test]
    fn u_messages_wcp_rejects_duplicate_and_bad_version() {
        let limits = limits();

        let mut duplicate = vec![1u8, 2, 0, 1, 0];
        duplicate.extend_from_slice(&field_bytes(0x10, &[0xAA]));
        duplicate.extend_from_slice(&field_bytes(0x10, &[0xBB]));
        assert_eq!(
            FieldMap::parse(&duplicate, &limits).unwrap_err(),
            WcpError::DuplicateField(0x10)
        );

        let bad_major = [1u8, 2, 0, 2, 0];
        assert_eq!(
            FieldMap::parse(&bad_major, &limits).unwrap_err(),
            WcpError::UnsupportedVersion(2)
        );

        let newer_minor = [1u8, 2, 0, 1, 1];
        assert_eq!(
            FieldMap::parse(&newer_minor, &limits)
                .unwrap()
                .version()
                .get(),
            0x0101
        );

        assert_eq!(
            FieldMap::parse(&[], &limits).unwrap_err(),
            WcpError::MissingVersion
        );
        assert_eq!(
            FieldMap::parse(&field_bytes(0x10, &[1]), &limits).unwrap_err(),
            WcpError::MissingVersion
        );
        assert_eq!(
            FieldMap::parse(&[1u8, 2, 0, 1, 0, 0x10, 5, 0, 1], &limits).unwrap_err(),
            WcpError::Malformed { offset: 5 }
        );

        let mut too_many = vec![1u8, 2, 0, 1, 0];
        for index in 0..64u8 {
            too_many.extend_from_slice(&field_bytes(0x10 + index, &[]));
        }
        assert_eq!(
            FieldMap::parse(&too_many, &limits).unwrap_err(),
            WcpError::TooManyFields {
                count: 65,
                max: MAX_FIELDS,
            }
        );
    }

    /// 44 §3.1 -- every type maps to one variant and one encoding direction.
    #[test]
    fn u_messages_message_table() {
        let limits = limits();
        let hello = Hello::new(
            ProtoVersion::CURRENT,
            Caps::REQUIRED,
            ClientId::from_bytes([7u8; 16]),
            [9u8; 32],
            [0xAA; AUTH_SEALED_LEN],
        );
        let welcome = Welcome {
            proto: ProtoVersion::CURRENT,
            caps: Caps::REQUIRED,
            epoch: 42,
            current_seq: Seq(9),
            client_id: ClientId::from_bytes([7u8; 16]),
            resync: ResyncMode::None,
            limits: WelcomeLimits {
                max_frame: 128 * 1024,
                credit_bytes: 8 * 1024 * 1024,
                session_ttl_s: 60,
                max_sessions: 32,
            },
            server_time: 1_700_000_000,
            server_nonce: [3u8; 32],
            session_id: SessionId(0),
        };
        let ordered_leave = ordered_leave_body();
        let ordered = Ordered::decode(&ordered_leave, &limits).unwrap();
        let response_body = WcpWriter::new().finish().unwrap();
        let response = Response {
            fields: FieldMap::parse(&response_body, &limits).unwrap(),
        };
        let relay_body = {
            let mut writer = WcpWriter::new();
            writer.u8(fid::F_SUB_KIND, RelaySub::Offer.as_u8());
            writer.finish().unwrap()
        };
        let relay = Relay {
            sub: RelaySub::Offer,
            fields: FieldMap::parse(&relay_body, &limits).unwrap(),
        };
        let ack = Ack { op_ids: &[] };
        let ping = Ping { client_time: 11 };
        let pong = Pong { server_time: 12 };
        let error = Error {
            reason: TrnReason::BadFrame,
            detail: b"bad",
            session_id: None,
        };
        let kick = Kick {
            reason: KickReason::HeartbeatTimeout,
        };
        let flow = Flow { grant_bytes: 4096 };
        let sync_end = SyncEnd {
            reason: SyncEndReason::Done,
            detail: Some(b"ok"),
        };
        let stream = StreamData { data: b"raw-chunk" };
        let leave = Leave {
            client_id: ClientId::from_bytes([5u8; 16]),
            reason: 1,
            last_signed_seq: 77,
        };
        let table: [(Message<'_>, MsgType); 14] = [
            (Message::Hello(hello), MsgType::HELLO),
            (Message::Welcome(welcome), MsgType::WELCOME),
            (Message::Ordered(ordered), MsgType::ORDERED),
            (Message::Response(response), MsgType::RESPONSE),
            (Message::Relay(relay), MsgType::RELAY),
            (Message::Ack(ack), MsgType::ACK),
            (Message::Ping(ping), MsgType::PING),
            (Message::Pong(pong), MsgType::PONG),
            (Message::Error(error), MsgType::ERROR),
            (Message::Kick(kick), MsgType::KICK),
            (Message::Flow(flow), MsgType::FLOW),
            (Message::SyncEnd(sync_end), MsgType::SYNC_END),
            (Message::StreamData(stream), MsgType::STREAM_DATA),
            (Message::Leave(leave), MsgType::LEAVE),
        ];

        assert_eq!(table.len(), MsgType::ALL.len());
        for (message, expected) in table {
            assert_eq!(message.msg_type(), expected);
            assert_eq!(message.body_encoding(), expected.body_encoding());
            assert_eq!(message.prefix_kind(), expected.prefix_kind());
            match expected.body_encoding() {
                BodyEncoding::Plain => {
                    let body = message.encode_plain().unwrap();
                    assert_eq!(
                        message.encode_sealed().unwrap_err(),
                        MessageError::WrongEncoding(expected)
                    );
                    assert_eq!(
                        decode_plain(expected, &body, &limits).unwrap().msg_type(),
                        expected
                    );
                }
                BodyEncoding::Sealed => {
                    assert_eq!(
                        message.encode_plain().unwrap_err(),
                        MessageError::WrongEncoding(expected)
                    );
                    let body = message.encode_sealed().unwrap();
                    if expected == MsgType::STREAM_DATA {
                        assert_eq!(
                            decode_plain(expected, &body, &limits).unwrap_err(),
                            MessageError::WrongEncoding(expected)
                        );
                        assert_eq!(
                            decode_sealed(expected, &body, &limits).unwrap_err(),
                            MessageError::WrongEncoding(expected)
                        );
                    } else {
                        assert_eq!(
                            decode_sealed(expected, &body, &limits).unwrap().msg_type(),
                            expected
                        );
                    }
                }
            }
        }
    }

    /// 44 §3.4 -- HELLO and WELCOME roundtrip.
    #[test]
    fn u_messages_hello_welcome_roundtrip() {
        let limits = limits();
        let hello = Hello::new(
            ProtoVersion::CURRENT,
            Caps::REQUIRED,
            ClientId::from_bytes([7u8; 16]),
            [9u8; 32],
            [0xAA; AUTH_SEALED_LEN],
        );
        let body = hello.encode().unwrap();
        assert_eq!(Hello::decode(&body, &limits).unwrap(), hello);

        let accepted = Welcome {
            proto: ProtoVersion::CURRENT,
            caps: Caps::REQUIRED,
            epoch: 42,
            current_seq: Seq(9),
            client_id: ClientId::from_bytes([7u8; 16]),
            resync: ResyncMode::Full,
            limits: WelcomeLimits {
                max_frame: 128 * 1024,
                credit_bytes: 8 * 1024 * 1024,
                session_ttl_s: 60,
                max_sessions: 32,
            },
            server_time: 1_700_000_000,
            server_nonce: [3u8; 32],
            session_id: SessionId(0),
        };
        let body = accepted.encode().unwrap();
        assert_eq!(Welcome::decode(&body, &limits).unwrap(), accepted);

        let other_session = Welcome {
            session_id: SessionId(5),
            ..accepted
        };
        let body = other_session.encode().unwrap();
        assert_eq!(Welcome::decode(&body, &limits).unwrap(), other_session);

        let body = rebuilt(&other_session.encode().unwrap(), &[], &[fid::F_SESSION_ID]);
        assert_eq!(
            Welcome::decode(&body, &limits).unwrap_err(),
            MessageError::Wcp(WcpError::MissingField(fid::F_SESSION_ID))
        );
    }

    #[test]
    fn hello_with_sealed_auth_fits_the_frame_limits() {
        let hello = Hello::new(
            ProtoVersion::CURRENT,
            Caps::REQUIRED,
            ClientId::from_bytes([7u8; 16]),
            [9u8; 32],
            [0xAA; AUTH_SEALED_LEN],
        );
        let body = hello.encode().unwrap();
        let limits = Limits::default();
        assert!(body.len() <= usize::from(limits.wcp_max));
        assert!(
            crate::protocol::HEADER_LEN
                + crate::protocol::CTRL_PREFIX_LEN
                + body.len()
                <= limits.ingress_frame as usize
        );
    }

    /// 44 §3.4 -- ERROR, KICK, FLOW, SYNC_END and LEAVE roundtrip.
    #[test]
    fn u_messages_error_kick_flow_syncend_leave_roundtrip() {
        let limits = limits();

        let error = Error {
            reason: TrnReason::BadFrame,
            detail: b"bad frame",
            session_id: Some(SessionId(3)),
        };
        let body = error.encode().unwrap();
        assert_eq!(Error::decode(&body, &limits).unwrap(), error);

        let kick = Kick {
            reason: KickReason::HeartbeatTimeout,
        };
        let body = kick.encode().unwrap();
        assert_eq!(Kick::decode(&body, &limits).unwrap(), kick);

        let flow = Flow { grant_bytes: 8192 };
        let body = flow.encode().unwrap();
        assert_eq!(Flow::decode(&body, &limits).unwrap(), flow);

        let sync_end = SyncEnd {
            reason: SyncEndReason::Cancel,
            detail: Some(b"cancelled"),
        };
        let body = sync_end.encode().unwrap();
        assert_eq!(SyncEnd::decode(&body, &limits).unwrap(), sync_end);

        let leave = Leave {
            client_id: ClientId::from_bytes([5u8; 16]),
            reason: 2,
            last_signed_seq: 77,
        };
        let body = leave.encode().unwrap();
        assert_eq!(Leave::decode(&body, &limits).unwrap(), leave);

        let long_detail = vec![0u8; usize::from(limits.detail_max) + 1];
        let too_long = Error {
            reason: TrnReason::Protocol,
            detail: &long_detail,
            session_id: None,
        };
        assert_eq!(
            Error::decode(&too_long.encode().unwrap(), &limits).unwrap_err(),
            MessageError::Wcp(WcpError::FieldTooLong {
                fid: fid::F_DETAIL,
                len: long_detail.len(),
                max: usize::from(limits.detail_max),
            })
        );
    }

    /// 44:INV-23 -- ORDERED WRITE, PWRITE and LEAVE roundtrip.
    #[test]
    fn u_messages_ordered_roundtrip() {
        let limits = limits();

        let write_body = ordered_write_body();
        let write = Ordered::decode(&write_body, &limits).unwrap();
        assert_eq!(write.op_class, OpClass::WRITE);
        assert_eq!(write.client_id, ClientId::from_bytes([1u8; 16]));
        assert_eq!(write.op_id, OpId::from_bytes([2u8; 16]));
        assert_eq!(write.path_str(), Some("/dir/file"));
        assert_eq!(
            write.attrs,
            Some(FileAttrs {
                mtime_ns: 1_700_000_000_000_000_000,
                uid: 1000,
                gid: 1000,
            })
        );
        let expected_data = DataRef {
            session: SessionId::from_le_bytes([5u8; 16]),
            total_len: 4096,
            data_hash: [6u8; 32],
        };
        assert_eq!(write.data(), Some(expected_data));
        assert_eq!(write.args, OpArgs::Write(expected_data));
        assert_eq!(write.encode_body(), write_body);
        let canonical = write.canonical_bytes_excluding(&[fid::F_PATH]).unwrap();
        let canonical_map = FieldMap::parse(&canonical, &limits).unwrap();
        assert!(canonical_map.get(fid::F_PATH).is_none());
        assert_eq!(
            canonical_map.get(fid::F_OP_ID),
            Some([2u8; 16].as_slice())
        );

        let pwrite_body = ordered_pwrite_body();
        let pwrite = Ordered::decode(&pwrite_body, &limits).unwrap();
        assert_eq!(
            pwrite.args,
            OpArgs::Pwrite {
                offset: 512,
                data: expected_data,
            }
        );
        assert_eq!(pwrite.encode_body(), pwrite_body);

        let leave_body = ordered_leave_body();
        let leave = Ordered::decode(&leave_body, &limits).unwrap();
        assert_eq!(leave.op_class, OpClass::LEAVE);
        assert!(leave.path.is_none());
        assert!(leave.attrs.is_none());
        assert_eq!(leave.args, OpArgs::Leave);
        assert!(leave.data().is_none());
        assert_eq!(leave.encode_body(), leave_body);
    }

    /// 44:INV-23 -- every required ORDERED field is enforced.
    #[test]
    fn u_messages_ordered_missing_field() {
        let limits = limits();
        let base = ordered_write_body();
        let required = [
            fid::F_CLIENT_ID,
            fid::F_OP_ID,
            fid::F_OP_CLASS,
            fid::F_PATH,
            fid::F_MTIME_NS,
            fid::F_UID,
            fid::F_GID,
            fid::F_DATA_SESSION,
            fid::F_TOTAL_LEN,
            fid::F_DATA_HASH,
        ];
        for field_id in required {
            let body = rebuilt(&base, &[], &[field_id]);
            assert_eq!(
                Ordered::decode(&body, &limits).unwrap_err(),
                MessageError::Wcp(WcpError::MissingField(field_id)),
                "field 0x{field_id:02x}"
            );
        }
    }

    /// 49:A14 -- unknown op_class is fatal, never skipped.
    #[test]
    fn u_messages_unknown_op_class_is_fatal() {
        let limits = limits();
        let base = ordered_write_body();
        for raw in [16u8, 255u8] {
            let body = rebuilt(&base, &[(fid::F_OP_CLASS, vec![raw])], &[fid::F_OP_CLASS]);
            let error = Ordered::decode(&body, &limits).unwrap_err();
            assert_eq!(error, MessageError::UnknownOpClass(raw));
            assert!(error.is_fatal());
            assert_eq!(
                decode_sealed(MsgType::ORDERED, &body, &limits).unwrap_err(),
                MessageError::UnknownOpClass(raw)
            );
        }
        assert!(!MessageError::Wcp(WcpError::MissingField(fid::F_OP_ID)).is_fatal());
        assert!(!MessageError::Path(PathError::Empty).is_fatal());
    }

    /// 44:R7 -- unknown fids survive parsing and are ignored by decoders.
    #[test]
    fn u_messages_unknown_fid_ignored() {
        let limits = limits();
        let hello = Hello::new(
            ProtoVersion::CURRENT,
            Caps::REQUIRED,
            ClientId::from_bytes([7u8; 16]),
            [9u8; 32],
            [0xAA; AUTH_SEALED_LEN],
        );
        let body = rebuilt(&hello.encode().unwrap(), &[(0x7E, b"vendor".to_vec())], &[]);
        assert_eq!(Hello::decode(&body, &limits).unwrap(), hello);

        let map = FieldMap::parse(&body, &limits).unwrap();
        assert_eq!(map.get(0x7E), Some(b"vendor".as_slice()));
        let full = map.canonical_bytes_excluding(&[]).unwrap();
        assert_eq!(
            FieldMap::parse(&full, &limits).unwrap().get(0x7E),
            Some(b"vendor".as_slice())
        );
        let filtered = map.canonical_bytes_excluding(&[0x7E]).unwrap();
        let filtered_map = FieldMap::parse(&filtered, &limits).unwrap();
        assert!(filtered_map.get(0x7E).is_none());
        assert!(filtered_map.get(fid::F_CLIENT_ID).is_some());
    }

    /// 44:V8 / 44 §3.5 -- canonical paths are validated, never rewritten.
    #[test]
    fn u_messages_path_norm() {
        for good in ["/", "/a", "/a/b", "/a/b.c", "/a-b_c"] {
            assert!(WirePath::parse(good, 4096).is_ok(), "{good}");
        }
        assert_eq!(WirePath::parse("", 4096), Err(PathError::Empty));
        assert_eq!(WirePath::parse("a", 4096), Err(PathError::NotAbsolute));
        assert_eq!(WirePath::parse("//a", 4096), Err(PathError::EmptySegment));
        assert_eq!(WirePath::parse("/a/", 4096), Err(PathError::TrailingSlash));
        assert_eq!(WirePath::parse("/a//b", 4096), Err(PathError::EmptySegment));
        assert_eq!(WirePath::parse("/a/./b", 4096), Err(PathError::DotSegment));
        assert_eq!(
            WirePath::parse("/a/../b", 4096),
            Err(PathError::ParentSegment)
        );
        assert_eq!(WirePath::parse("/a\0b", 4096), Err(PathError::Nul));

        let long = format!("/{}", "a".repeat(4096));
        assert_eq!(
            WirePath::parse(&long, 4096),
            Err(PathError::TooLong {
                len: 4097,
                max: 4096,
            })
        );
        assert!(WirePath::parse(&long[..4096], 4096).is_ok());

        let a = WirePath::parse("/a", 4096).unwrap();
        let b = WirePath::parse("/b", 4096).unwrap();
        assert_eq!(a.as_str(), "/a");
        assert_eq!(a.len(), 2);
        assert_eq!(a.hash(), a.hash());
        assert_ne!(a.hash(), b.hash());
    }

    /// 44:V6 -- protocol negotiation and WCP version matrix.
    #[test]
    fn u_messages_version_matrix() {
        let caps = Caps::REQUIRED.union(Caps::ZSTD);
        let negotiated = negotiate(
            ProtoVersion { major: 3, minor: 5 },
            ProtoVersion { major: 3, minor: 2 },
            caps.union(Caps::BATCH_BROADCAST),
            caps,
        )
        .unwrap();
        assert_eq!(negotiated.proto, ProtoVersion { major: 3, minor: 2 });
        assert_eq!(negotiated.caps, caps);
        assert!(!negotiated.caps.contains(Caps::BATCH_BROADCAST));

        assert_eq!(
            negotiate(
                ProtoVersion { major: 2, minor: 0 },
                ProtoVersion { major: 3, minor: 0 },
                Caps::REQUIRED,
                Caps::REQUIRED,
            )
            .unwrap_err(),
            VersionError::MajorMismatch {
                local: 2,
                remote: 3,
            }
        );
        assert_eq!(
            negotiate(
                ProtoVersion::CURRENT,
                ProtoVersion::V2_0,
                Caps::REQUIRED,
                Caps::REQUIRED,
            )
            .unwrap_err(),
            VersionError::MajorMismatch {
                local: 3,
                remote: 2,
            }
        );
        assert_eq!(
            negotiate(
                ProtoVersion::CURRENT,
                ProtoVersion::CURRENT,
                Caps::REQUIRED.without(Caps::PSK_AUTH),
                Caps::REQUIRED,
            )
            .unwrap_err(),
            VersionError::MissingCapability(Caps::PSK_AUTH)
        );
        assert!(matches!(
            negotiate(
                ProtoVersion::CURRENT,
                ProtoVersion::CURRENT,
                Caps::REQUIRED.without(Caps::CHACHA8_POLY1305),
                Caps::REQUIRED,
            )
            .unwrap_err(),
            VersionError::MissingCapability(_)
        ));

        let limits = limits();
        for (raw, accepted) in [(1u16, true), (0x0101, true), (2u16, false)] {
            let mut body = vec![1u8, 2, 0];
            body.extend_from_slice(&raw.to_le_bytes());
            assert_eq!(
                FieldMap::parse(&body, &limits).is_ok(),
                accepted,
                "WCP version 0x{raw:04x}"
            );
        }
    }

    /// A 2.0 `HELLO` carries no `F_AUTH`. The version check must run before
    /// the decoder asks for that field, so the peer sees a version mismatch.
    #[test]
    fn old_v2_hello_is_a_version_rejection_not_a_parse_error() {
        let mut writer = WcpWriter::new();
        writer.u16(fid::F_PROTO_MAJOR, 2);
        writer.u16(fid::F_PROTO_MINOR, 0);
        writer.u32(fid::F_CAPS, Caps::REQUIRED.bits());
        writer.bytes(fid::F_CLIENT_ID, &[0x11; 16]);
        writer.bytes(fid::F_CLIENT_NONCE, &[0x22; 32]);
        let body = writer.finish().unwrap();

        assert_eq!(peek_proto(&body, &limits()).unwrap(), ProtoVersion::V2_0);
        assert_eq!(
            decode_plain(MsgType::HELLO, &body, &limits()).unwrap_err(),
            MessageError::ProtocolVersion {
                local: 3,
                remote: 2
            }
        );
    }

    /// A complete current-format `HELLO` still decodes.
    #[test]
    fn current_hello_passes_the_version_check() {
        let hello = Hello::new(
            ProtoVersion::CURRENT,
            Caps::REQUIRED,
            ClientId::from_bytes([0x11; 16]),
            [0x22; 32],
            [0x33; AUTH_SEALED_LEN],
        );
        let body = hello.encode().unwrap();
        assert_eq!(
            decode_plain(MsgType::HELLO, &body, &limits())
                .unwrap()
                .msg_type(),
            MsgType::HELLO
        );
    }

    /// A 2.0 `WELCOME` lacks the proof and the sealed `ACCEPT`. The version
    /// check must reject it before those fields are inspected.
    #[test]
    fn old_v2_welcome_is_a_version_rejection_not_a_parse_error() {
        let mut welcome = welcome_fixture();
        welcome.proto = ProtoVersion::V2_0;
        let body = welcome.encode().unwrap();

        assert_eq!(
            decode_plain(MsgType::WELCOME, &body, &limits()).unwrap_err(),
            MessageError::ProtocolVersion {
                local: 3,
                remote: 2
            }
        );
        assert!(
            MessageError::ProtocolVersion {
                local: 3,
                remote: 2
            }
            .is_fatal()
        );
    }

    /// 44:V12 -- replay dedup keeps the minimum seq; the gate is strict.
    #[test]
    fn u_messages_dedup() {
        let a = OpId::from_bytes([1u8; 16]);
        let b = OpId::from_bytes([2u8; 16]);
        let c = OpId::from_bytes([3u8; 16]);

        let mut log = OpIdLog::new(2);
        assert_eq!(log.observe(a, Seq(5)), OpIdVerdict::Fresh);
        assert_eq!(log.observe(a, Seq(7)), OpIdVerdict::Duplicate);
        assert_eq!(log.observe(a, Seq(3)), OpIdVerdict::Earlier);
        assert_eq!(log.get(a), Some(Seq(3)));
        assert_eq!(log.observe(a, Seq(3)), OpIdVerdict::Duplicate);
        assert_eq!(log.observe(a, Seq(2)), OpIdVerdict::Earlier);
        assert_eq!(log.get(a), Some(Seq(2)));
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());

        assert_eq!(log.observe(b, Seq(1)), OpIdVerdict::Fresh);
        assert_eq!(log.observe(c, Seq(1)), OpIdVerdict::Fresh);
        assert_eq!(log.len(), 2);
        assert_eq!(log.capacity(), 2);
        assert_eq!(log.get(a), None);
        assert_eq!(log.get(b), Some(Seq(1)));
        assert_eq!(log.get(c), Some(Seq(1)));

        let mut zero = OpIdLog::new(0);
        assert_eq!(zero.capacity(), 1);
        assert!(zero.is_empty());
        assert_eq!(zero.observe(a, Seq(1)), OpIdVerdict::Fresh);
        assert_eq!(zero.len(), 1);
        let default_log = OpIdLog::default();
        assert_eq!(default_log.capacity(), DEFAULT_OP_ID_CAPACITY);
        assert_eq!(
            OpIdLog::new(DEFAULT_OP_ID_CAPACITY).capacity(),
            DEFAULT_OP_ID_CAPACITY
        );

        let mut gate = SeqGate::new();
        assert_eq!(gate.next(), Seq(1));
        assert_eq!(gate.observe(Seq::UNSEQUENCED), SeqVerdict::Unsequenced);
        assert_eq!(gate.observe(Seq(2)), SeqVerdict::Gap { expected: 1 });
        assert_eq!(gate.next(), Seq(1));
        assert_eq!(gate.observe(Seq(1)), SeqVerdict::Next);
        assert_eq!(gate.observe(Seq(1)), SeqVerdict::Duplicate);
        assert_eq!(gate.observe(Seq(3)), SeqVerdict::Gap { expected: 2 });
        assert_eq!(gate.observe(Seq(2)), SeqVerdict::Next);
        assert_eq!(gate.observe(Seq(3)), SeqVerdict::Next);
        assert_eq!(gate.next(), Seq(4));
        assert_eq!(SeqGate::default().next(), Seq(1));
    }

    /// 44 §3.1 -- plain and sealed decoders reject the other domain.
    #[test]
    fn u_messages_decode_rejects_wrong_encoding() {
        let limits = limits();
        assert_eq!(
            decode_plain(MsgType::ORDERED, &[], &limits).unwrap_err(),
            MessageError::WrongEncoding(MsgType::ORDERED)
        );
        assert_eq!(
            decode_sealed(MsgType::HELLO, &[], &limits).unwrap_err(),
            MessageError::WrongEncoding(MsgType::HELLO)
        );
        assert_eq!(
            decode_plain(MsgType::STREAM_DATA, b"raw", &limits).unwrap_err(),
            MessageError::WrongEncoding(MsgType::STREAM_DATA)
        );
        assert_eq!(
            decode_sealed(MsgType::STREAM_DATA, b"raw", &limits).unwrap_err(),
            MessageError::WrongEncoding(MsgType::STREAM_DATA)
        );

        let stream = Message::StreamData(StreamData { data: b"raw" });
        assert_eq!(stream.encode_sealed().unwrap(), b"raw");
        assert_eq!(
            stream.encode_plain().unwrap_err(),
            MessageError::WrongEncoding(MsgType::STREAM_DATA)
        );
    }

    proptest! {
        /// 44 §3.3 -- arbitrary writer-built maps roundtrip through the parser.
        #[test]
        fn u_messages_prop_wcp_roundtrip(
            fields in proptest::collection::vec(
                (2u8..=255u8, proptest::collection::vec(any::<u8>(), 0..=24)),
                0..=12,
            )
        ) {
            let limits = limits();
            let mut seen = HashSet::new();
            let mut writer = WcpWriter::new();
            let mut expected: Vec<(u8, Vec<u8>)> = Vec::new();
            for (field_id, value) in fields {
                if field_id == fid::F_WCP_VER || !seen.insert(field_id) {
                    continue;
                }
                writer.bytes(field_id, &value);
                expected.push((field_id, value));
            }
            let body = writer.finish().unwrap();
            let map = FieldMap::parse(&body, &limits).unwrap();
            prop_assert_eq!(map.len(), expected.len() + 1);
            for (field_id, value) in expected {
                prop_assert_eq!(map.get(field_id), Some(value.as_slice()));
            }
            let canonical = map.canonical_bytes_excluding(&[]).unwrap();
            let reparsed = FieldMap::parse(&canonical, &limits).unwrap();
            prop_assert_eq!(reparsed.len(), map.len());
        }

        /// 44:V10 -- arbitrary bytes never panic the WCP parser.
        #[test]
        fn u_messages_prop_parse_never_panics(
            buf in proptest::collection::vec(any::<u8>(), 0..=256)
        ) {
            let _ = FieldMap::parse(&buf, &limits());
        }
    }
}
