//! Event kinds, the versioned payload codec and the row types.
//!
//! `events.kind` is a text column and `events.payload` is opaque bytes. The
//! two are tied together by [`EventPayload::kind`]: a payload knows which kind
//! it belongs to, and [`EventPayload::decode`] rejects a row whose kind does
//! not match. Callers therefore never pass a kind and a payload independently.
//!
//! # Payload format
//!
//! ```text
//! version:u8  ||  bincode(serde) EventPayload
//! ```
//!
//! Version 2 is current. It appended `size` to `setattr`, so a version-1
//! `setattr` decodes as an attribute-only change with `size: None`, exactly
//! the operation version 1 recorded. Every other variant has the same layout
//! in both versions, so only `setattr` needs a legacy decoder. New payloads
//! are always written as version 2.
//!
//! The version byte is the escape hatch for a future layout change. The
//! bincode body is length-limited on decode so a corrupt or hostile row cannot
//! ask for an unbounded allocation.

use serde::{Deserialize, Serialize};

use super::types::ChunkRef;
use super::{Result, StoreError, now_secs};

/// Current payload encoding version.
pub const PAYLOAD_VERSION: u8 = 2;

/// First payload version, still accepted on decode.
///
/// Versions 1 and 2 differ only in `setattr`; every other variant decodes
/// with the current layout.
pub const PAYLOAD_VERSION_V1: u8 = 1;

/// Bincode's enum tag of `EventPayload::Setattr`, frozen at version 1.
///
/// Version 2 keeps the variant order, so the tag is unchanged. The legacy
/// decoder reads it explicitly because it does not decode an `EventPayload`.
const SETATTR_TAG: u32 = 5;

/// Upper bound on a payload body, matching the design's 4 MiB event ceiling.
///
/// A `write` carries chunk references, not content, so ordinary payloads are a
/// few KiB. The bound also keeps a compacted `write` (which lists a whole
/// file's chunks) decodable; beyond it, encoding is refused rather than
/// writing a row that cannot be read back.
pub const MAX_PAYLOAD_BYTES: usize = 4 << 20;

fn codec_config() -> impl bincode::config::Config {
    bincode::config::standard().with_limit::<MAX_PAYLOAD_BYTES>()
}

/// The operation a row describes. The text values are the `events.kind` check
/// list and are a wire-visible contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EventKind {
    CreateFile,
    CreateDir,
    Symlink,
    Write,
    Truncate,
    Setattr,
    Rename,
    Unlink,
    Rmdir,
    Link,
    Lock,
    Unlock,
    Leave,
    SyncCtrl,
}

impl EventKind {
    /// The exact text stored in `events.kind`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreateFile => "create_file",
            Self::CreateDir => "create_dir",
            Self::Symlink => "symlink",
            Self::Write => "write",
            Self::Truncate => "truncate",
            Self::Setattr => "setattr",
            Self::Rename => "rename",
            Self::Unlink => "unlink",
            Self::Rmdir => "rmdir",
            Self::Link => "link",
            Self::Lock => "lock",
            Self::Unlock => "unlock",
            Self::Leave => "leave",
            Self::SyncCtrl => "sync_ctrl",
        }
    }

    /// Parse the `events.kind` text.
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "create_file" => Self::CreateFile,
            "create_dir" => Self::CreateDir,
            "symlink" => Self::Symlink,
            "write" => Self::Write,
            "truncate" => Self::Truncate,
            "setattr" => Self::Setattr,
            "rename" => Self::Rename,
            "unlink" => Self::Unlink,
            "rmdir" => Self::Rmdir,
            "link" => Self::Link,
            "lock" => Self::Lock,
            "unlock" => Self::Unlock,
            "leave" => Self::Leave,
            "sync_ctrl" => Self::SyncCtrl,
            _ => return None,
        })
    }
}

impl std::fmt::Display for EventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The structured, versioned body of one event.
///
/// Paths are not duplicated here: `events.path` and `events.path2` carry them.
/// `create_*` and `symlink` carry the attributes so a replay does not need a
/// separate lookup, and `write` carries the chunk references so the receiver
/// can fetch content by hash.
///
/// The variant order is the bincode tag and part of the stored format. Never
/// reorder or remove a variant; append new ones at the end and bump
/// [`PAYLOAD_VERSION`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventPayload {
    CreateFile {
        ino: [u8; 16],
        mode: u32,
        uid: u32,
        gid: u32,
        mtime_ns: i64,
        file_root: [u8; 32],
    },
    CreateDir {
        ino: [u8; 16],
        mode: u32,
        uid: u32,
        gid: u32,
        mtime_ns: i64,
        file_root: [u8; 32],
    },
    Symlink {
        ino: [u8; 16],
        mode: u32,
        uid: u32,
        gid: u32,
        mtime_ns: i64,
        target: Vec<u8>,
        file_root: [u8; 32],
    },
    Write {
        ino: [u8; 16],
        /// First byte written.
        offset: u64,
        /// Bytes written.
        len: u64,
        /// Resulting file size.
        size: u64,
        file_root: [u8; 32],
        mtime_ns: i64,
        /// Chunks covering the written range, in ascending `chunk_no`.
        chunks: Vec<ChunkRef>,
    },
    Truncate {
        ino: [u8; 16],
        /// Resulting file size.
        size: u64,
        file_root: [u8; 32],
        mtime_ns: i64,
    },
    Setattr {
        ino: [u8; 16],
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        mtime_ns: Option<i64>,
        /// Resulting file size when this event also truncates. `None` for an
        /// attribute-only change.
        size: Option<u64>,
    },
    Rename {
        ino: [u8; 16],
    },
    Unlink {
        ino: [u8; 16],
    },
    Rmdir {
        ino: [u8; 16],
    },
    Link {
        ino: [u8; 16],
    },
    Lock {
        ino: [u8; 16],
        start: u64,
        len: u64,
        exclusive: bool,
    },
    Unlock {
        ino: [u8; 16],
        start: u64,
        len: u64,
    },
    Leave,
    SyncCtrl {
        code: i64,
    },
}

impl EventPayload {
    /// The kind this payload must be stored under.
    pub const fn kind(&self) -> EventKind {
        match self {
            Self::CreateFile { .. } => EventKind::CreateFile,
            Self::CreateDir { .. } => EventKind::CreateDir,
            Self::Symlink { .. } => EventKind::Symlink,
            Self::Write { .. } => EventKind::Write,
            Self::Truncate { .. } => EventKind::Truncate,
            Self::Setattr { .. } => EventKind::Setattr,
            Self::Rename { .. } => EventKind::Rename,
            Self::Unlink { .. } => EventKind::Unlink,
            Self::Rmdir { .. } => EventKind::Rmdir,
            Self::Link { .. } => EventKind::Link,
            Self::Lock { .. } => EventKind::Lock,
            Self::Unlock { .. } => EventKind::Unlock,
            Self::Leave => EventKind::Leave,
            Self::SyncCtrl { .. } => EventKind::SyncCtrl,
        }
    }

    /// The object this payload mutates, if any.
    pub const fn ino(&self) -> Option<[u8; 16]> {
        Some(match self {
            Self::CreateFile { ino, .. }
            | Self::CreateDir { ino, .. }
            | Self::Symlink { ino, .. }
            | Self::Write { ino, .. }
            | Self::Truncate { ino, .. }
            | Self::Setattr { ino, .. }
            | Self::Rename { ino }
            | Self::Unlink { ino }
            | Self::Rmdir { ino }
            | Self::Link { ino }
            | Self::Lock { ino, .. }
            | Self::Unlock { ino, .. } => *ino,
            Self::Leave | Self::SyncCtrl { .. } => return None,
        })
    }

    /// Chunks introduced or updated by this payload.
    ///
    /// Only `write` carries them. A `truncate` keeps the file prefix and
    /// zero-fills or cuts the tail, so the applier derives the zero chunks
    /// locally instead of receiving a list that could be as large as the file.
    pub fn chunks(&self) -> &[ChunkRef] {
        match self {
            Self::Write { chunks, .. } => chunks,
            _ => &[],
        }
    }

    /// Encode with the version byte prepended.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let body = bincode::serde::encode_to_vec(self, codec_config())
            .map_err(|err| StoreError::Codec(format!("encode: {err}")))?;
        let mut out = Vec::with_capacity(body.len() + 1);
        out.push(PAYLOAD_VERSION);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decode and verify that the payload belongs to `kind`.
    pub fn decode(kind: EventKind, bytes: &[u8]) -> Result<Self> {
        let Some((&version, body)) = bytes.split_first() else {
            return Err(StoreError::Codec("empty payload".to_owned()));
        };
        let payload = match version {
            PAYLOAD_VERSION => decode_body(body, "payload")?,
            PAYLOAD_VERSION_V1 if kind == EventKind::Setattr => decode_setattr_v1(body)?,
            PAYLOAD_VERSION_V1 => decode_body(body, "payload")?,
            found => {
                return Err(StoreError::PayloadVersion {
                    found,
                    supported: PAYLOAD_VERSION,
                })
            }
        };
        let actual = payload.kind();
        if actual != kind {
            return Err(StoreError::PayloadKindMismatch {
                kind: kind.as_str(),
                payload: actual.as_str(),
            });
        }
        Ok(payload)
    }
}

/// A version-1 `setattr` body: the enum tag, then the five fields it had.
///
/// An externally tagged bincode enum is `u32 tag || variant fields`, so a
/// struct decodes the same bytes when its first field is the tag. The tag is
/// checked so a corrupt or mismatched body cannot pose as a `setattr`.
#[derive(Deserialize)]
struct SetattrV1 {
    tag: u32,
    ino: [u8; 16],
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    mtime_ns: Option<i64>,
}

/// Decode one bincode body and require that it consumes every byte.
fn decode_body<T: serde::de::DeserializeOwned>(body: &[u8], what: &str) -> Result<T> {
    let (value, used): (T, usize) = bincode::serde::decode_from_slice(body, codec_config())
        .map_err(|err| StoreError::Codec(format!("decode {what}: {err}")))?;
    if used != body.len() {
        return Err(StoreError::Codec("trailing payload bytes".to_owned()));
    }
    Ok(value)
}

/// Decode the version-1 `setattr` body into the current payload.
fn decode_setattr_v1(body: &[u8]) -> Result<EventPayload> {
    let legacy: SetattrV1 = decode_body(body, "v1 setattr")?;
    if legacy.tag != SETATTR_TAG {
        return Err(StoreError::Codec(format!(
            "v1 setattr has variant tag {}, expected {SETATTR_TAG}",
            legacy.tag
        )));
    }
    Ok(EventPayload::Setattr {
        ino: legacy.ino,
        mode: legacy.mode,
        uid: legacy.uid,
        gid: legacy.gid,
        mtime_ns: legacy.mtime_ns,
        size: None,
    })
}

/// Version-1 `setattr` bytes, as written before the payload gained `size`.
///
/// Layout: version 1, enum tag 5, ino `[0x11; 16]`, `Some(0o644)`,
/// `Some(1000)`, `Some(1001)`, `Some(1_700_000_000_000_000_000)`. Bincode uses
/// one byte for integers up to 250, then `0xFB` plus a little-endian `u16` (or
/// `0xFD` plus a `u64`); a signed value is zigzag-encoded first. The bytes are
/// frozen; do not regenerate them from the current encoder.
#[cfg(test)]
pub(crate) const V1_SETATTR_BYTES: [u8; 40] = [
    1, 5, //
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, //
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, //
    1, 0xfb, 0xa4, 0x01, // mode: Some(0o644)
    1, 0xfb, 0xe8, 0x03, // uid: Some(1000)
    1, 0xfb, 0xe9, 0x03, // gid: Some(1001)
    1, 0xfd, 0x00, 0x00, 0x54, 0x6c, 0xfc, 0x39, 0x2f, 0x2f, // mtime_ns
];

/// A row waiting to be inserted into `events`.
#[derive(Clone, Debug)]
pub struct EventDraft {
    /// `None` means "the current `meta.epoch`"; `Some` must match it.
    pub epoch: Option<i64>,
    pub op_id: Option<[u8; 16]>,
    pub session_id: Option<[u8; 16]>,
    /// Source path; `None` only for `leave` and `sync_ctrl`.
    pub path: Option<String>,
    /// Destination path; `Some` only for `rename` and `link`.
    pub path2: Option<String>,
    pub payload: EventPayload,
    pub result: String,
    pub created_at: i64,
}

impl EventDraft {
    /// A normal path-bearing operation.
    pub fn new(op_id: [u8; 16], payload: EventPayload, path: impl Into<String>) -> Self {
        Self {
            epoch: None,
            op_id: Some(op_id),
            session_id: None,
            path: Some(path.into()),
            path2: None,
            payload,
            result: "ok".to_owned(),
            created_at: now_secs(),
        }
    }

    /// A server-injected `leave` for a closed session. `leave` is the only
    /// kind allowed to omit `op_id`.
    pub fn leave(session_id: [u8; 16]) -> Self {
        Self {
            epoch: None,
            op_id: None,
            session_id: Some(session_id),
            path: None,
            path2: None,
            payload: EventPayload::Leave,
            result: "ok".to_owned(),
            created_at: now_secs(),
        }
    }

    /// A control marker with no object effect.
    pub fn sync_ctrl(op_id: [u8; 16], code: i64) -> Self {
        Self {
            epoch: None,
            op_id: Some(op_id),
            session_id: None,
            path: None,
            path2: None,
            payload: EventPayload::SyncCtrl { code },
            result: "ok".to_owned(),
            created_at: now_secs(),
        }
    }

    /// Require a specific epoch instead of accepting the current one.
    pub fn with_epoch(mut self, epoch: i64) -> Self {
        self.epoch = Some(epoch);
        self
    }

    /// Attach the session that owns a lock or that is leaving.
    pub fn with_session(mut self, session_id: [u8; 16]) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Set the destination path for `rename` or `link`.
    pub fn with_path2(mut self, path: impl Into<String>) -> Self {
        self.path2 = Some(path.into());
        self
    }

    /// Set the result text (`ok` or a rejection reason).
    pub fn with_result(mut self, result: impl Into<String>) -> Self {
        self.result = result.into();
        self
    }

    /// Override the creation timestamp.
    pub fn with_created_at(mut self, created_at: i64) -> Self {
        self.created_at = created_at;
        self
    }

    /// Check that the path/op/session shape matches the payload kind.
    pub fn validate(&self) -> Result<EventKind> {
        let kind = self.payload.kind();
        let path_required = !matches!(kind, EventKind::Leave | EventKind::SyncCtrl);
        let path2_required = matches!(kind, EventKind::Rename | EventKind::Link);
        let session_required =
            matches!(kind, EventKind::Lock | EventKind::Unlock | EventKind::Leave);

        if kind != EventKind::Leave && self.op_id.is_none() {
            return Err(StoreError::InvalidEvent {
                kind: kind.as_str(),
                reason: "op_id is required",
            });
        }
        if path_required && self.path.is_none() {
            return Err(StoreError::InvalidEvent {
                kind: kind.as_str(),
                reason: "path is required",
            });
        }
        if !path_required && self.path.is_some() {
            return Err(StoreError::InvalidEvent {
                kind: kind.as_str(),
                reason: "path is not allowed",
            });
        }
        if path2_required && self.path2.is_none() {
            return Err(StoreError::InvalidEvent {
                kind: kind.as_str(),
                reason: "path2 is required",
            });
        }
        if !path2_required && self.path2.is_some() {
            return Err(StoreError::InvalidEvent {
                kind: kind.as_str(),
                reason: "path2 is not allowed",
            });
        }
        if session_required && self.session_id.is_none() {
            return Err(StoreError::InvalidEvent {
                kind: kind.as_str(),
                reason: "session_id is required",
            });
        }
        Ok(kind)
    }
}

/// A row read back from `events`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRow {
    pub seq: i64,
    pub epoch: i64,
    pub op_id: Option<[u8; 16]>,
    pub session_id: Option<[u8; 16]>,
    pub kind: EventKind,
    pub path: Option<String>,
    pub path2: Option<String>,
    pub ino: Option<[u8; 16]>,
    pub payload: Vec<u8>,
    pub result: String,
    pub applied: bool,
    pub created_at: i64,
}

impl EventRow {
    /// Decode the payload and verify it matches the stored kind.
    pub fn decode(&self) -> Result<EventPayload> {
        EventPayload::decode(self.kind, &self.payload)
    }
}

/// The outcome of appending one event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InsertedEvent {
    pub seq: i64,
    /// BLAKE3 of the encoded payload; the value stored in `op_ids`.
    pub payload_hash: [u8; 32],
}
