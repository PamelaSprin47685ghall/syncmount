//! Pure translation between `ORDERED` frames, `state::Op` and stored events.
//!
//! # Role
//!
//! The server needs four translations and nothing else:
//!
//! * a decoded `ORDERED` becomes a [`WireOp`]: the flat, owned form the store
//!   carries across its command channel;
//! * a [`WireOp`] plus its assembled content becomes a `state::Op`, so
//!   `state::plan` can decide it;
//! * a committed `state::Op` becomes an `EventDraft`, so the event log can
//!   rebuild the same state on replay;
//! * a stored `EventRow` becomes a sealed `ORDERED` frame again, plus the
//!   content stream a `WRITE` needs.
//!
//! # Boundaries
//!
//! This module is pure: no SQL, no clock, no I/O, no actor. It reads no key
//! except the [`PskKeyRing`] it is given and it never decides policy. A
//! refusal is always [`Reject`]; the caller turns it into the point-to-point
//! `ERROR` detail with [`reject_body`].
//!
//! # Replay contract
//!
//! A replay frame must pass the same decoder as a live frame, so every
//! mandatory field is present and well formed. The values a live sender
//! derives from its own state are placeholders here: the receiver reads the
//! authoritative operation from `F_EXTRA`, which carries the versioned
//! `EventPayload` byte for byte. `F_CLIENT_ID` is zero because the PSK
//! session already authenticates the frame.
//!
//! `seq` is outside the AEAD additional data, so a replay frame is sealed
//! once and then stamped per receiver with [`with_seq`]. The ciphertext does
//! not change.

use crate::protocol::crypto::{CryptoError, NonceMinter, PskKeyRing, Sealer};
use crate::protocol::messages::fid;
use crate::protocol::{
    CHUNK_PLAIN, DataRef, FileAttrs, Flags, FrameDecoder, FrameHeader, FrameRef, Limits, MsgType,
    OpArgs, OpClass, Ordered, Prefix, ProtocolError, RoutePrefix, Seq, SessionId, StreamId,
    WcpError, WcpWriter, encode_frame,
};
use crate::state::{
    self, Attrs, CHUNK_BYTES, Chunk, Errno, Ino, LockType, Op, Path, Reject, Session, State,
};
use crate::store::sqlite::{ChunkRef, EventDraft, EventKind, EventPayload, EventRow, RejectState};

/// Plaintext width of one chunk.
const CHUNK: usize = CHUNK_BYTES as usize;

/// `F_LOCK_ACTION` value that asks for a lock. Frozen by the protocol.
const LOCK_ACTION_SET: u8 = 0;

/// `F_LOCK_ACTION` value that releases a range. Frozen by the protocol.
const LOCK_ACTION_UNLOCK: u8 = 2;

/// One decoded `ORDERED` in owned, class-agnostic form.
///
/// The fields are the union of every class; the class decides which ones
/// carry meaning. [`WireOp::from_ordered`] fills them from the field map, and
/// [`to_op`] reads only the ones its class defines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireOp {
    /// Operation identity; zero only when the sender omitted it.
    pub op_id: [u8; 16],
    /// Operation class.
    pub class: OpClass,
    /// Absolute path, empty for classes without one.
    pub path: String,
    /// `RENAME` destination.
    pub path2: Option<String>,
    /// `SYMLINK` contents or `LINK` source, as bytes.
    pub target: Option<Vec<u8>>,
    /// `MKDIR`, `CREATE_EXCL` or `SETATTR` mode.
    pub mode: Option<u32>,
    /// Owner uid from `F_UID`.
    pub uid: u32,
    /// Owner gid from `F_GID`.
    pub gid: u32,
    /// Modification time from `F_MTIME_NS`.
    pub mtime_ns: u64,
    /// Data stream reference for `WRITE` and `PWRITE`.
    pub data: Option<DataRef>,
    /// `PWRITE` offset.
    pub offset: Option<u64>,
    /// `TRUNCATE` length.
    pub length: Option<u64>,
    /// Lock mode: `0` read, `1` write.
    pub lock_type: Option<u8>,
    /// Lock action: `0` set, `2` unlock.
    pub lock_action: Option<u8>,
    /// Lock range start.
    pub lock_start: Option<u64>,
    /// Lock range length; `0` means "to end of file".
    pub lock_len: Option<u64>,
}

impl WireOp {
    /// Flatten one decoded `ORDERED`.
    ///
    /// The decoder has already enforced the per-class field rules, so this
    /// function only copies. It still refuses a file op without a path: a
    /// caller that skipped the decoder must not get a silently empty path.
    pub fn from_ordered(ordered: &Ordered<'_>) -> Result<Self, Reject> {
        let path = match ordered.path_str() {
            Some(path) => path.to_owned(),
            None if ordered.op_class.requires_file_attrs() => {
                return Err(Reject::new(Errno::EINVAL, "ORDERED file op has no path"));
            }
            None => String::new(),
        };
        let attrs = ordered.attrs.unwrap_or(FileAttrs {
            mtime_ns: 0,
            uid: 0,
            gid: 0,
        });
        let mut op = Self {
            op_id: ordered.op_id.to_bytes(),
            class: ordered.op_class,
            path,
            path2: None,
            target: None,
            mode: None,
            uid: attrs.uid,
            gid: attrs.gid,
            mtime_ns: attrs.mtime_ns,
            data: None,
            offset: None,
            length: None,
            lock_type: None,
            lock_action: None,
            lock_start: None,
            lock_len: None,
        };
        match &ordered.args {
            OpArgs::Write(data) => op.data = Some(*data),
            OpArgs::Pwrite { offset, data } => {
                op.offset = Some(*offset);
                op.data = Some(*data);
            }
            OpArgs::Truncate { length } => op.length = Some(*length),
            OpArgs::Setattr { mode, size } => {
                op.mode = *mode;
                op.length = *size;
            }
            OpArgs::Rename { path2 } => op.path2 = Some(path2.as_str().to_owned()),
            OpArgs::Mkdir { mode } => op.mode = Some(*mode),
            OpArgs::Link { target } => op.target = Some(target.as_str().as_bytes().to_vec()),
            OpArgs::Symlink { target } => op.target = Some(target.as_bytes().to_vec()),
            OpArgs::CreateExcl { mode, .. } => op.mode = Some(*mode),
            OpArgs::Flock { lock_type, action } => {
                op.lock_type = Some(*lock_type);
                op.lock_action = Some(*action);
            }
            OpArgs::FcntlLock {
                lock_type,
                action,
                start,
                len,
            } => {
                op.lock_type = Some(*lock_type);
                op.lock_action = Some(*action);
                op.lock_start = Some(*start);
                op.lock_len = Some(*len);
            }
            OpArgs::Unlink | OpArgs::Rmdir | OpArgs::SyncCtrl | OpArgs::Leave => {}
        }
        Ok(op)
    }

    /// The inode this operation creates or mutates.
    ///
    /// An operation id is 128 random bits, so the low half is already a
    /// stable identity for a create. Zero is reserved for the root, so a
    /// zero id maps to `1`.
    pub fn derive_ino(&self) -> u128 {
        let ino = u128::from_le_bytes(self.op_id);
        if ino == 0 { 1 } else { ino }
    }
}

/// Split plaintext into chunk references plus the bytes of each chunk.
///
/// The chunk size is the protocol constant, and every hash is
/// `BLAKE3(plaintext)` of that chunk. An empty file has no chunks.
pub fn split_chunks(data: &[u8]) -> Vec<(Chunk, Vec<u8>)> {
    data.chunks(CHUNK)
        .map(|piece| (chunk_of(piece), piece.to_vec()))
        .collect()
}

/// Turn one wire operation into the state-machine operation to plan.
///
/// `content` is the complete post-operation file content that the store
/// assembled: for `WRITE` it is the written stream, for `PWRITE` it is the
/// whole file after the patch, and for `TRUNCATE` it is the resized file.
/// The state machine replaces a file's whole chunk list, so it never sees a
/// patch.
///
/// `Ok(None)` means "accepted, but no state change": `FLOCK` is local to the
/// client and `SYNC_CTRL` is unused in v1. The caller still sequences such an
/// operation as a `sync_ctrl` event.
///
/// `state` is accepted so the caller passes the same snapshot it will plan
/// against. This function does not consult it: the store performs the
/// read-modify-write that produces `content`.
pub fn to_op(
    op: &WireOp,
    content: Option<&[u8]>,
    _state: &State,
    session: Session,
) -> Result<Option<Op>, Reject> {
    let path = path_bytes(&op.path);
    let mtime_ns = op.mtime_ns;
    let planned = match op.class {
        OpClass::CREATE_EXCL => Op::CreateFile {
            path,
            ino: op.derive_ino(),
            mode: require_mode(op)?,
            uid: op.uid,
            gid: op.gid,
            mtime_ns,
        },
        OpClass::MKDIR => Op::CreateDir {
            path,
            ino: op.derive_ino(),
            mode: require_mode(op)?,
            uid: op.uid,
            gid: op.gid,
            mtime_ns,
        },
        OpClass::SYMLINK => Op::Symlink {
            path,
            ino: op.derive_ino(),
            target: require_target(op)?,
            uid: op.uid,
            gid: op.gid,
            mtime_ns,
        },
        OpClass::WRITE | OpClass::PWRITE => Op::Write {
            path,
            chunks: chunks_of(require_content(content)?),
            mtime_ns,
        },
        OpClass::TRUNCATE => Op::Truncate {
            path,
            size: op
                .length
                .ok_or_else(|| Reject::new(Errno::EINVAL, "TRUNCATE requires F_LENGTH"))?,
            chunks: chunks_of(require_content(content)?),
            mtime_ns,
        },
        OpClass::SETATTR => {
            let size = op.length;
            let chunks = match size {
                Some(_) => chunks_of(require_content(content)?),
                None => Vec::new(),
            };
            Op::SetAttr {
                path,
                attrs: Attrs {
                    mode: op.mode,
                    // `F_MTIME_NS` is part of every file-class ORDERED. A
                    // pure attribute change must still carry the requested
                    // timestamp: `utimensat` is a `setattr` without a size.
                    // Zero means the client asked to keep the current value.
                    mtime_ns: (mtime_ns != 0).then_some(mtime_ns),
                    ..Attrs::default()
                },
                size,
                chunks,
            }
        }
        OpClass::RENAME => Op::Rename {
            from: path,
            to: path_bytes(
                op.path2
                    .as_deref()
                    .ok_or_else(|| Reject::new(Errno::EINVAL, "RENAME requires F_PATH2"))?,
            ),
            mtime_ns,
        },
        OpClass::UNLINK => Op::Unlink { path, mtime_ns },
        OpClass::RMDIR => Op::Rmdir { path, mtime_ns },
        OpClass::LINK => Op::Link {
            target: require_target(op)?,
            path,
            mtime_ns,
        },
        OpClass::FLOCK | OpClass::SYNC_CTRL => return Ok(None),
        OpClass::FCNTL_LOCK => {
            let start = op.lock_start.unwrap_or(0);
            let end = range_end(start, op.lock_len.unwrap_or(0));
            if op.lock_action == Some(LOCK_ACTION_UNLOCK) {
                Op::Unlock {
                    path,
                    session,
                    start,
                    end,
                }
            } else {
                Op::Lock {
                    path,
                    session,
                    typ: lock_type(op.lock_type.unwrap_or(0))?,
                    start,
                    end,
                }
            }
        }
        OpClass::LEAVE => Op::Leave { session },
        _ => return Err(Reject::new(Errno::ENOSYS, "unsupported op class")),
    };
    Ok(Some(planned))
}

/// Build the event that records one planned operation.
///
/// The payload matches `planned`, not `op`: the state machine is the
/// authority on what happened. `state_before` supplies the inode of an
/// existing object; a create takes its inode from the operation itself.
/// `session` is the author session, which owns a lock and identifies a leave.
pub fn event_for(op: &WireOp, planned: &Op, state_before: &State, session: [u8; 16]) -> EventDraft {
    let (payload, path2) = match planned {
        Op::Leave { .. } => return EventDraft::leave(session),
        Op::CreateFile {
            ino,
            mode,
            uid,
            gid,
            mtime_ns,
            ..
        } => (
            EventPayload::CreateFile {
                ino: ino_bytes(*ino),
                mode: *mode,
                uid: *uid,
                gid: *gid,
                mtime_ns: ns_i64(*mtime_ns),
                file_root: state::empty_file_root(),
            },
            None,
        ),
        Op::CreateDir {
            ino,
            mode,
            uid,
            gid,
            mtime_ns,
            ..
        } => (
            EventPayload::CreateDir {
                ino: ino_bytes(*ino),
                mode: *mode,
                uid: *uid,
                gid: *gid,
                mtime_ns: ns_i64(*mtime_ns),
                file_root: state::dir_root(),
            },
            None,
        ),
        Op::Symlink {
            ino,
            target,
            uid,
            gid,
            mtime_ns,
            ..
        } => (
            EventPayload::Symlink {
                ino: ino_bytes(*ino),
                mode: 0o777,
                uid: *uid,
                gid: *gid,
                mtime_ns: ns_i64(*mtime_ns),
                target: target.clone(),
                file_root: state::symlink_root(target),
            },
            None,
        ),
        Op::Write {
            path,
            chunks,
            mtime_ns,
        } => {
            let size = total_len(chunks);
            (
                EventPayload::Write {
                    ino: ino_bytes(resolve_or(state_before, path, op)),
                    offset: op.offset.unwrap_or(0),
                    len: op.data.map_or(size, |data| data.total_len),
                    size,
                    file_root: state::file_root(chunks),
                    mtime_ns: ns_i64(*mtime_ns),
                    chunks: chunk_refs(chunks),
                },
                None,
            )
        }
        Op::Truncate {
            path,
            size,
            chunks,
            mtime_ns,
        } => (
            EventPayload::Truncate {
                ino: ino_bytes(resolve_or(state_before, path, op)),
                size: *size,
                file_root: state::file_root(chunks),
                mtime_ns: ns_i64(*mtime_ns),
            },
            None,
        ),
        Op::SetAttr {
            path,
            attrs,
            size,
            ..
        } => (
            EventPayload::Setattr {
                ino: ino_bytes(resolve_or(state_before, path, op)),
                mode: attrs.mode,
                uid: attrs.uid,
                gid: attrs.gid,
                mtime_ns: attrs.mtime_ns.map(ns_i64),
                size: *size,
            },
            None,
        ),
        Op::Rename { from, to, mtime_ns } => (
            EventPayload::Rename {
                ino: ino_bytes(resolve_or(state_before, from, op)),
                mtime_ns: Some(ns_i64(*mtime_ns)),
            },
            Some(
                op.path2
                    .clone()
                    .unwrap_or_else(|| String::from_utf8_lossy(to).into_owned()),
            ),
        ),
        Op::Unlink { path, mtime_ns } => (
            EventPayload::Unlink {
                ino: ino_bytes(resolve_or(state_before, path, op)),
                mtime_ns: Some(ns_i64(*mtime_ns)),
            },
            None,
        ),
        Op::Rmdir { path, mtime_ns } => (
            EventPayload::Rmdir {
                ino: ino_bytes(resolve_or(state_before, path, op)),
                mtime_ns: Some(ns_i64(*mtime_ns)),
            },
            None,
        ),
        Op::Link {
            target, mtime_ns, ..
        } => (
            EventPayload::Link {
                ino: ino_bytes(resolve_or(state_before, target, op)),
                mtime_ns: Some(ns_i64(*mtime_ns)),
            },
            Some(String::from_utf8_lossy(target).into_owned()),
        ),
        Op::Lock {
            path,
            typ,
            start,
            end,
            ..
        } => (
            EventPayload::Lock {
                ino: ino_bytes(resolve_or(state_before, path, op)),
                start: *start,
                len: range_len(*start, *end),
                exclusive: *typ == LockType::Write,
            },
            None,
        ),
        Op::Unlock {
            path, start, end, ..
        } => (
            EventPayload::Unlock {
                ino: ino_bytes(resolve_or(state_before, path, op)),
                start: *start,
                len: range_len(*start, *end),
            },
            None,
        ),
    };
    let mut draft = EventDraft::new(op.op_id, payload, op.path.clone());
    if let Some(path2) = path2 {
        draft = draft.with_path2(path2);
    }
    if matches!(planned, Op::Lock { .. } | Op::Unlock { .. }) {
        draft = draft.with_session(session);
    }
    draft
}

/// Encode the `ERROR` detail of a semantic rejection.
///
/// Layout: `op_id 16 B | errno i32 LE | state_len u32 LE | state (bincode,
/// optional) | reason UTF-8`. The state is self-delimiting, so the reason can
/// follow it; the receiver decodes it at a fixed offset and ignores the
/// trailing text.
///
/// A state that does not fit `detail_max` is not sent. `state_len` becomes
/// `u32::MAX` and the reason is truncated; the receiver replays the server
/// log instead. The returned detail is never longer than `detail_max`, and it
/// is empty when `detail_max` cannot even hold the fixed header.
pub fn reject_body(
    op_id: [u8; 16],
    reject: Reject,
    state: Option<&RejectState>,
    detail_max: usize,
) -> Vec<u8> {
    /// `op_id`, `errno` and `state_len`.
    const HEADER: usize = 16 + 4 + 4;
    if detail_max < HEADER {
        return Vec::new();
    }
    let reason = reject.reason.as_bytes();
    let encoded = state
        .and_then(|state| {
            bincode::serde::encode_to_vec(state, bincode::config::standard()).ok()
        })
        .unwrap_or_default();
    let full = HEADER + encoded.len() + reason.len() <= detail_max;
    let mut out = Vec::with_capacity(if full {
        HEADER + encoded.len() + reason.len()
    } else {
        detail_max
    });
    out.extend_from_slice(&op_id);
    out.extend_from_slice(&reject.errno.raw().to_le_bytes());
    if full {
        out.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        out.extend_from_slice(&encoded);
        out.extend_from_slice(reason);
    } else {
        // The receiver sees the sentinel and asks for a replay; no state and
        // no complete reason can follow it.
        out.extend_from_slice(&u32::MAX.to_le_bytes());
        out.extend_from_slice(&reason[..reason.len().min(detail_max - HEADER)]);
    }
    out
}

/// The content stream that belongs to one replayed `WRITE`.
///
/// The receiver applies the stream as the complete file content, so it must
/// arrive before the `ORDERED` frame that names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayContent {
    /// Data session; the `RoutePrefix` session of every `STREAM_DATA` frame.
    pub session: SessionId,
    /// Plaintext length of `data`.
    pub total_len: u64,
    /// Concatenated chunk plaintext, in payload order.
    pub data: Vec<u8>,
}

/// Assemble the content stream of a stored `write` event.
///
/// `chunk` resolves one chunk hash to its bytes; the store backs it with its
/// chunk table. The function returns `None` for any other event kind and for
/// a missing chunk: a partial stream would corrupt the receiver, so it is
/// better to replay nothing and let the session resynchronize.
pub fn replay_content(
    event: &EventRow,
    mut chunk: impl FnMut(&[u8; 32]) -> Option<Vec<u8>>,
) -> Option<ReplayContent> {
    if event.kind != EventKind::Write {
        return None;
    }
    let EventPayload::Write { chunks, .. } = event.decode().ok()? else {
        return None;
    };
    let mut data = Vec::new();
    for reference in &chunks {
        data.extend_from_slice(&chunk(&reference.hash)?);
    }
    Some(ReplayContent {
        session: replay_data_session(event),
        total_len: data.len() as u64,
        data,
    })
}

/// The `F_DATA_SESSION` value that a replay frame and its stream share.
///
/// It is derived from the event, so the sender of the content and the reader
/// of the `ORDERED` agree without extra state. A `leave` has no op id, so its
/// sequence number stands in; both mappings are non-zero.
pub fn replay_data_session(event: &EventRow) -> SessionId {
    SessionId::new(u128::from_le_bytes(replay_op_id(event)))
}

/// Synthesize the sealed `ORDERED` frame of one stored event.
///
/// The frame is unsequenced; stamp it per receiver with [`with_seq`]. The
/// `F_TOTAL_LEN` and `F_DATA_HASH` fields describe the payload's chunk list,
/// not the content stream. Use [`replay_ordered_with_content`] to make them
/// exact.
pub fn replay_ordered(
    event: &EventRow,
    ring: &PskKeyRing,
    nonces: &NonceMinter,
) -> Result<Vec<u8>, WireError> {
    replay_ordered_with_content(event, ring, nonces, None)
}

/// Synthesize a sealed `ORDERED` frame with the write content known.
///
/// `content` is the byte stream [`replay_content`] returned for the same
/// event. When it is present, `F_TOTAL_LEN` and `F_DATA_HASH` match the
/// stream the receiver will assemble.
pub fn replay_ordered_with_content(
    event: &EventRow,
    ring: &PskKeyRing,
    nonces: &NonceMinter,
    content: Option<&[u8]>,
) -> Result<Vec<u8>, WireError> {
    let payload = event
        .decode()
        .map_err(|error| WireError::Payload(error.to_string()))?;
    let body = replay_body(event, &payload, content)?;
    let prefix = Prefix::None;
    let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);
    let key = ring.session_key();
    let sealed = Sealer::with_session_key(&key, nonces).seal(&mut header, &prefix, &body)?;
    let sealed = sealed.into_vec();
    Ok(encode_frame(&FrameRef::new(&header, &prefix, &sealed))?)
}

/// Build the live content stream that accompanies a rebuilt `ORDERED`.
///
/// The frames use the event-derived data session, so the receiver pairs them
/// with the `F_DATA_SESSION` that [`replay_ordered_with_content`] wrote. A
/// live broadcast must send these frames before the `ORDERED`: the author's
/// original stream has a random session id and carries only the patched
/// chunks, not the server's complete file.
pub fn replay_content_frames(
    event: &EventRow,
    ring: &PskKeyRing,
    nonces: &NonceMinter,
    data: &[u8],
) -> Result<Vec<Vec<u8>>, WireError> {
    let session = replay_data_session(event);
    let mut frames = Vec::with_capacity(2 + data.len().div_ceil(CHUNK_PLAIN));
    let open_prefix = Prefix::Route(RoutePrefix::new(session, StreamId::CTRL, 0, 0));
    let open_body = WcpWriter::new().finish()?;
    frames.push(seal_replay_frame(
        MsgType::RELAY,
        Flags::ENC.with(Flags::ROUTED),
        open_prefix,
        &open_body,
        ring,
        nonces,
    )?);
    let total_chunks = data.len().div_ceil(CHUNK_PLAIN).max(1) as u32;
    for index in 0..total_chunks {
        let start = index as usize * CHUNK_PLAIN;
        let end = (start + CHUNK_PLAIN).min(data.len());
        let prefix = Prefix::Route(RoutePrefix::new(
            session,
            StreamId::OP_DATA,
            index,
            total_chunks,
        ));
        frames.push(seal_replay_frame(
            MsgType::STREAM_DATA,
            Flags::ENC.with(Flags::ROUTED),
            prefix,
            &data[start..end],
            ring,
            nonces,
        )?);
    }
    Ok(frames)
}

/// Seal one replay or live-content frame with the session key.
fn seal_replay_frame(
    msg_type: MsgType,
    flags: Flags,
    prefix: Prefix,
    body: &[u8],
    ring: &PskKeyRing,
    nonces: &NonceMinter,
) -> Result<Vec<u8>, WireError> {
    let mut header = FrameHeader::new(msg_type, flags, 0, Seq::UNSEQUENCED);
    let sealed =
        Sealer::with_session_key(&ring.session_key(), nonces).seal(&mut header, &prefix, body)?;
    Ok(encode_frame(&FrameRef::new(&header, &prefix, sealed.as_bytes()))?)
}

/// Rewrite the sequence number of one encoded frame.
///
/// `seq` is outside the AEAD additional data, so the body stays
/// byte-identical and every receiver authenticates it as before. The input
/// must be exactly one complete frame; trailing bytes are a protocol error,
/// not a frame to ignore.
pub fn with_seq(frame: &[u8], seq: Seq) -> Result<Vec<u8>, WireError> {
    let mut decoder = FrameDecoder::new(Limits::protocol());
    decoder.push(frame)?;
    let decoded = decoder.next_frame_owned()?.ok_or(WireError::NotAFrame)?;
    if !decoder.is_empty() {
        return Err(WireError::NotAFrame);
    }
    let (header, prefix, body) = decoded.into_parts();
    let header = header.with_seq(seq);
    Ok(encode_frame(&FrameRef::new(&header, &prefix, &body))?)
}

/// A replay or frame-rewrite failure.
#[derive(Debug)]
pub enum WireError {
    /// A frame could not be decoded or encoded.
    Protocol(ProtocolError),
    /// AEAD sealing failed.
    Crypto(CryptoError),
    /// The `WCP` body is malformed or too large for one frame.
    Body(WcpError),
    /// The stored payload is not decodable.
    Payload(String),
    /// The bytes are not exactly one complete frame.
    NotAFrame,
    /// The stored row cannot produce a well-formed frame.
    Incomplete(&'static str),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "{error}"),
            Self::Crypto(error) => write!(f, "{error}"),
            Self::Body(error) => write!(f, "{error}"),
            Self::Payload(error) => write!(f, "event payload: {error}"),
            Self::NotAFrame => f.write_str("not exactly one complete frame"),
            Self::Incomplete(reason) => write!(f, "stored event is incomplete: {reason}"),
        }
    }
}

impl std::error::Error for WireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Crypto(error) => Some(error),
            Self::Body(error) => Some(error),
            Self::Payload(_) | Self::NotAFrame | Self::Incomplete(_) => None,
        }
    }
}

impl From<ProtocolError> for WireError {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl From<CryptoError> for WireError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<WcpError> for WireError {
    fn from(value: WcpError) -> Self {
        Self::Body(value)
    }
}

/// Encode the body of one replay frame.
fn replay_body(
    event: &EventRow,
    payload: &EventPayload,
    content: Option<&[u8]>,
) -> Result<Vec<u8>, WireError> {
    let class = replay_class(payload.kind());
    let mut writer = WcpWriter::new();
    writer.bytes(fid::F_CLIENT_ID, &[0u8; 16]);
    writer.u8(fid::F_OP_CLASS, class.get());
    writer.bytes(fid::F_OP_ID, &replay_op_id(event));
    if class.requires_file_attrs() {
        let path = match event.path.as_deref() {
            Some(path) if !path.is_empty() => path,
            // `SYNC_CTRL` is a file class by wire definition but carries no
            // path; the root is the only canonical path that fits.
            _ if payload.kind() == EventKind::SyncCtrl => "/",
            _ => return Err(WireError::Incomplete("event has no path")),
        };
        writer.str(fid::F_PATH, path);
        writer.u64(fid::F_MTIME_NS, payload_mtime_ns(payload));
        writer.u32(fid::F_UID, payload_uid(payload));
        writer.u32(fid::F_GID, payload_gid(payload));
    }
    match payload {
        EventPayload::CreateFile { mode, .. } => {
            writer.u32(fid::F_MODE, *mode);
            writer.u32(fid::F_OP_FLAGS, 0);
        }
        EventPayload::CreateDir { mode, .. } => {
            writer.u32(fid::F_MODE, *mode);
        }
        EventPayload::Symlink { target, .. } => {
            writer.bytes(fid::F_TARGET, target);
        }
        EventPayload::Write { chunks, .. } => {
            let total_len = content.map_or_else(
                || chunks.iter().map(|chunk| u64::from(chunk.len)).sum(),
                |data| data.len() as u64,
            );
            let data_hash =
                content.map_or_else(|| refs_hash(chunks), |data| *blake3::hash(data).as_bytes());
            writer.bytes(
                fid::F_DATA_SESSION,
                &replay_data_session(event).to_le_bytes(),
            );
            writer.u64(fid::F_TOTAL_LEN, total_len);
            writer.bytes(fid::F_DATA_HASH, &data_hash);
        }
        EventPayload::Truncate { size, .. } => {
            writer.u64(fid::F_LENGTH, *size);
        }
        EventPayload::Setattr { mode, size, .. } => {
            if let Some(mode) = mode {
                writer.u32(fid::F_MODE, *mode);
            }
            if let Some(size) = size {
                writer.u64(fid::F_LENGTH, *size);
            }
        }
        EventPayload::Rename { .. } => {
            let path2 = event
                .path2
                .as_deref()
                .ok_or(WireError::Incomplete("rename event has no path2"))?;
            writer.str(fid::F_PATH2, path2);
        }
        EventPayload::Link { .. } => {
            // The new path is `F_PATH`; `F_TARGET` names the existing one.
            let target = event
                .path2
                .as_deref()
                .ok_or(WireError::Incomplete("link event has no path2"))?;
            writer.str(fid::F_TARGET, target);
        }
        EventPayload::Lock {
            start,
            len,
            exclusive,
            ..
        } => {
            writer.u8(fid::F_LOCK_TYPE, u8::from(*exclusive));
            writer.u8(fid::F_LOCK_ACTION, LOCK_ACTION_SET);
            writer.u64(fid::F_LOCK_START, *start);
            writer.u64(fid::F_LOCK_LEN, *len);
        }
        EventPayload::Unlock { start, len, .. } => {
            writer.u8(fid::F_LOCK_TYPE, 0);
            writer.u8(fid::F_LOCK_ACTION, LOCK_ACTION_UNLOCK);
            writer.u64(fid::F_LOCK_START, *start);
            writer.u64(fid::F_LOCK_LEN, *len);
        }
        EventPayload::Unlink { .. }
        | EventPayload::Rmdir { .. }
        | EventPayload::Leave
        | EventPayload::SyncCtrl { .. } => {}
    }
    writer.bytes(fid::F_EXTRA, &event.payload);
    Ok(writer.finish()?)
}

/// The wire class that carries one event kind.
const fn replay_class(kind: EventKind) -> OpClass {
    match kind {
        EventKind::CreateFile => OpClass::CREATE_EXCL,
        EventKind::CreateDir => OpClass::MKDIR,
        EventKind::Symlink => OpClass::SYMLINK,
        EventKind::Write => OpClass::WRITE,
        EventKind::Truncate => OpClass::TRUNCATE,
        EventKind::Setattr => OpClass::SETATTR,
        EventKind::Rename => OpClass::RENAME,
        EventKind::Unlink => OpClass::UNLINK,
        EventKind::Rmdir => OpClass::RMDIR,
        EventKind::Link => OpClass::LINK,
        EventKind::Lock => OpClass::FCNTL_LOCK,
        EventKind::Unlock => OpClass::FCNTL_LOCK,
        EventKind::Leave => OpClass::LEAVE,
        EventKind::SyncCtrl => OpClass::SYNC_CTRL,
    }
}

/// The `F_OP_ID` of a replay frame.
///
/// A `leave` event has no op id. Its sequence number stands in, so every
/// frame still carries a non-zero identity.
fn replay_op_id(event: &EventRow) -> [u8; 16] {
    if let Some(op_id) = event.op_id {
        return op_id;
    }
    let seq = u64::try_from(event.seq).unwrap_or(0);
    let raw = if seq == 0 { 1 } else { u128::from(seq) };
    raw.to_le_bytes()
}

fn payload_mtime_ns(payload: &EventPayload) -> u64 {
    match payload {
        EventPayload::CreateFile { mtime_ns, .. }
        | EventPayload::CreateDir { mtime_ns, .. }
        | EventPayload::Symlink { mtime_ns, .. }
        | EventPayload::Write { mtime_ns, .. }
        | EventPayload::Truncate { mtime_ns, .. } => ns_u64(*mtime_ns),
        EventPayload::Setattr { mtime_ns, .. } => mtime_ns.map_or(0, ns_u64),
        EventPayload::Rename { mtime_ns, .. }
        | EventPayload::Unlink { mtime_ns, .. }
        | EventPayload::Rmdir { mtime_ns, .. }
        | EventPayload::Link { mtime_ns, .. } => mtime_ns.map_or(0, ns_u64),
        _ => 0,
    }
}

fn payload_uid(payload: &EventPayload) -> u32 {
    match payload {
        EventPayload::CreateFile { uid, .. }
        | EventPayload::CreateDir { uid, .. }
        | EventPayload::Symlink { uid, .. } => *uid,
        EventPayload::Setattr { uid, .. } => uid.unwrap_or(0),
        _ => 0,
    }
}

fn payload_gid(payload: &EventPayload) -> u32 {
    match payload {
        EventPayload::CreateFile { gid, .. }
        | EventPayload::CreateDir { gid, .. }
        | EventPayload::Symlink { gid, .. } => *gid,
        EventPayload::Setattr { gid, .. } => gid.unwrap_or(0),
        _ => 0,
    }
}

/// A stand-in `F_DATA_HASH` when the caller has no content bytes.
///
/// The receiver takes the authoritative operation from `F_EXTRA`, so this
/// value only has to be deterministic.
fn refs_hash(chunks: &[ChunkRef]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for reference in chunks {
        hasher.update(&reference.hash);
    }
    *hasher.finalize().as_bytes()
}

fn chunk_of(piece: &[u8]) -> Chunk {
    Chunk::new(*blake3::hash(piece).as_bytes(), piece.len() as u32)
}

fn chunks_of(data: &[u8]) -> Vec<Chunk> {
    data.chunks(CHUNK).map(chunk_of).collect()
}

fn chunk_refs(chunks: &[Chunk]) -> Vec<ChunkRef> {
    let mut offset = 0u64;
    chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| {
            let reference = ChunkRef {
                chunk_no: index as u32,
                hash: chunk.hash,
                offset,
                len: chunk.len,
            };
            offset += u64::from(chunk.len);
            reference
        })
        .collect()
}

fn path_bytes(text: &str) -> Path {
    text.as_bytes().to_vec()
}

fn require_mode(op: &WireOp) -> Result<u32, Reject> {
    op.mode
        .ok_or_else(|| Reject::new(Errno::EINVAL, "op class requires F_MODE"))
}

fn require_target(op: &WireOp) -> Result<Path, Reject> {
    op.target
        .clone()
        .ok_or_else(|| Reject::new(Errno::EINVAL, "op class requires F_TARGET"))
}

fn require_content(content: Option<&[u8]>) -> Result<&[u8], Reject> {
    content.ok_or_else(|| Reject::new(Errno::EINVAL, "op class requires assembled content"))
}

fn lock_type(raw: u8) -> Result<LockType, Reject> {
    match raw {
        0 => Ok(LockType::Read),
        1 => Ok(LockType::Write),
        _ => Err(Reject::new(Errno::EINVAL, "unknown lock type")),
    }
}

/// The inclusive end of a lock range; length `0` means "to end of file".
fn range_end(start: u64, len: u64) -> u64 {
    if len == 0 {
        u64::MAX
    } else {
        start.saturating_add(len - 1)
    }
}

/// The length of an inclusive range; `u64::MAX` end means "to end of file".
fn range_len(start: u64, end: u64) -> u64 {
    if end == u64::MAX {
        0
    } else {
        end.saturating_sub(start).saturating_add(1)
    }
}

fn resolve_or(state: &State, path: &[u8], op: &WireOp) -> Ino {
    state.resolve(path).unwrap_or_else(|_| op.derive_ino())
}

fn total_len(chunks: &[Chunk]) -> u64 {
    chunks.iter().map(|chunk| u64::from(chunk.len)).sum()
}

fn ino_bytes(ino: Ino) -> [u8; 16] {
    ino.to_le_bytes()
}

fn ns_i64(ns: u64) -> i64 {
    i64::try_from(ns).unwrap_or(i64::MAX)
}

fn ns_u64(ns: i64) -> u64 {
    u64::try_from(ns).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::protocol::crypto::{Opener, PskSalt};
    use crate::protocol::{FrameBuf, OpId};
    use crate::state::{empty_file_root, file_root};

    const SESSION: [u8; 16] = [0x5a; 16];

    fn ring() -> PskKeyRing {
        PskKeyRing::derive(&[7u8; 32], &PskSalt::DEFAULT).unwrap()
    }

    fn nonces() -> NonceMinter {
        NonceMinter::with_instance(0x1234)
    }

    fn wire_op(class: OpClass, path: &str) -> WireOp {
        WireOp {
            op_id: [0x22; 16],
            class,
            path: path.to_owned(),
            path2: None,
            target: None,
            mode: None,
            uid: 11,
            gid: 12,
            mtime_ns: 13,
            data: None,
            offset: None,
            length: None,
            lock_type: None,
            lock_action: None,
            lock_start: None,
            lock_len: None,
        }
    }

    fn state_with_file() -> State {
        let mut state = State::new();
        state
            .apply(&Op::CreateFile {
                path: b"/f".to_vec(),
                ino: 7,
                mode: 0o644,
                uid: 1,
                gid: 2,
                mtime_ns: 3,
            })
            .unwrap();
        state
    }

    fn ordered_body(build: impl FnOnce(&mut WcpWriter)) -> Vec<u8> {
        let mut writer = WcpWriter::new();
        build(&mut writer);
        writer.finish().unwrap()
    }

    fn common(writer: &mut WcpWriter, class: OpClass, op_id: [u8; 16]) {
        writer.bytes(fid::F_CLIENT_ID, &[0u8; 16]);
        writer.u8(fid::F_OP_CLASS, class.get());
        writer.bytes(fid::F_OP_ID, &op_id);
    }

    fn row(
        kind: EventKind,
        payload: EventPayload,
        path: Option<&str>,
        path2: Option<&str>,
    ) -> EventRow {
        EventRow {
            seq: 5,
            epoch: 1,
            op_id: Some([0x77; 16]),
            session_id: None,
            kind,
            path: path.map(str::to_owned),
            path2: path2.map(str::to_owned),
            ino: payload.ino(),
            payload: payload.encode().unwrap(),
            result: "ok".to_owned(),
            applied: true,
            created_at: 0,
        }
    }

    fn decode_frame(bytes: &[u8], ring: &PskKeyRing) -> (FrameBuf, Vec<u8>) {
        let mut decoder = FrameDecoder::new(Limits::protocol());
        decoder.push(bytes).unwrap();
        let frame = decoder.next_frame_owned().unwrap().unwrap();
        assert!(decoder.is_empty());
        let key = ring.session_key();
        let plain = Opener::with_session_key(&key)
            .open(&frame.header, &frame.prefix, &frame.body)
            .unwrap();
        (frame, plain.as_slice().to_vec())
    }

    #[test]
    fn derive_ino_reads_the_op_id_little_endian() {
        let mut op = wire_op(OpClass::CREATE_EXCL, "/a");
        op.op_id = [0x01; 16];
        assert_eq!(op.derive_ino(), u128::from_le_bytes([0x01; 16]));

        op.op_id = [0u8; 16];
        assert_eq!(op.derive_ino(), 1, "zero is the root inode");
    }

    #[test]
    fn split_chunks_splits_at_the_protocol_chunk_size() {
        assert!(split_chunks(&[]).is_empty());

        let one = vec![0xa5u8; 1];
        let chunks = split_chunks(&one);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].0.len, 1);
        assert_eq!(chunks[0].0.hash, *blake3::hash(&one).as_bytes());
        assert_eq!(chunks[0].1, one);

        assert_eq!(split_chunks(&vec![0x11u8; 65_536]).len(), 1);

        let over = vec![0x22u8; 65_537];
        let chunks = split_chunks(&over);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].0.len, 65_536);
        assert_eq!(chunks[1].0.len, 1);
        assert_eq!(chunks[1].1, vec![0x22u8]);
        assert_eq!(
            chunks
                .iter()
                .map(|(chunk, _)| u64::from(chunk.len))
                .sum::<u64>(),
            65_537
        );
    }

    #[test]
    fn from_ordered_reads_paths_modes_and_targets() {
        let body = ordered_body(|writer| {
            common(writer, OpClass::CREATE_EXCL, [0x11; 16]);
            writer.str(fid::F_PATH, "/new");
            writer.u64(fid::F_MTIME_NS, 1_700_000_000);
            writer.u32(fid::F_UID, 1000);
            writer.u32(fid::F_GID, 1001);
            writer.u32(fid::F_MODE, 0o640);
            writer.u32(fid::F_OP_FLAGS, 0o102);
        });
        let ordered = Ordered::decode(&body, &Limits::protocol()).unwrap();
        let op = WireOp::from_ordered(&ordered).unwrap();
        assert_eq!(op.op_id, [0x11; 16]);
        assert_eq!(op.class, OpClass::CREATE_EXCL);
        assert_eq!(op.path, "/new");
        assert_eq!(op.mode, Some(0o640));
        assert_eq!(op.uid, 1000);
        assert_eq!(op.gid, 1001);
        assert_eq!(op.mtime_ns, 1_700_000_000);
        assert!(op.path2.is_none() && op.target.is_none() && op.data.is_none());

        let body = ordered_body(|writer| {
            common(writer, OpClass::RENAME, [0x12; 16]);
            writer.str(fid::F_PATH, "/from");
            writer.str(fid::F_PATH2, "/to");
            writer.u64(fid::F_MTIME_NS, 5);
            writer.u32(fid::F_UID, 1);
            writer.u32(fid::F_GID, 2);
        });
        let ordered = Ordered::decode(&body, &Limits::protocol()).unwrap();
        let op = WireOp::from_ordered(&ordered).unwrap();
        assert_eq!(op.path, "/from");
        assert_eq!(op.path2.as_deref(), Some("/to"));

        let body = ordered_body(|writer| {
            common(writer, OpClass::LINK, [0x13; 16]);
            writer.str(fid::F_PATH, "/new-link");
            writer.str(fid::F_TARGET, "/existing");
            writer.u64(fid::F_MTIME_NS, 5);
            writer.u32(fid::F_UID, 1);
            writer.u32(fid::F_GID, 2);
        });
        let ordered = Ordered::decode(&body, &Limits::protocol()).unwrap();
        let op = WireOp::from_ordered(&ordered).unwrap();
        assert_eq!(op.path, "/new-link");
        assert_eq!(op.target.as_deref(), Some(&b"/existing"[..]));

        let body = ordered_body(|writer| {
            common(writer, OpClass::SYMLINK, [0x14; 16]);
            writer.str(fid::F_PATH, "/sym");
            writer.str(fid::F_TARGET, "../relative");
            writer.u64(fid::F_MTIME_NS, 5);
            writer.u32(fid::F_UID, 1);
            writer.u32(fid::F_GID, 2);
        });
        let ordered = Ordered::decode(&body, &Limits::protocol()).unwrap();
        let op = WireOp::from_ordered(&ordered).unwrap();
        assert_eq!(op.target.as_deref(), Some(&b"../relative"[..]));
        assert_eq!(op.mode, None);
    }

    #[test]
    fn from_ordered_reads_data_and_lock_fields() {
        let body = ordered_body(|writer| {
            common(writer, OpClass::PWRITE, [0x21; 16]);
            writer.str(fid::F_PATH, "/f");
            writer.u64(fid::F_MTIME_NS, 5);
            writer.u32(fid::F_UID, 1);
            writer.u32(fid::F_GID, 2);
            writer.u64(fid::F_OFFSET, 4096);
            writer.bytes(fid::F_DATA_SESSION, &[0x33; 16]);
            writer.u64(fid::F_TOTAL_LEN, 7);
            writer.bytes(fid::F_DATA_HASH, &[0x44; 32]);
        });
        let ordered = Ordered::decode(&body, &Limits::protocol()).unwrap();
        let op = WireOp::from_ordered(&ordered).unwrap();
        assert_eq!(op.offset, Some(4096));
        let data = op.data.unwrap();
        assert_eq!(data.total_len, 7);
        assert_eq!(data.session, SessionId::from_le_bytes([0x33; 16]));
        assert_eq!(data.data_hash, [0x44; 32]);

        let body = ordered_body(|writer| {
            common(writer, OpClass::FCNTL_LOCK, [0x22; 16]);
            writer.str(fid::F_PATH, "/f");
            writer.u64(fid::F_MTIME_NS, 5);
            writer.u32(fid::F_UID, 1);
            writer.u32(fid::F_GID, 2);
            writer.u8(fid::F_LOCK_TYPE, 1);
            writer.u8(fid::F_LOCK_ACTION, 0);
            writer.u64(fid::F_LOCK_START, 10);
            writer.u64(fid::F_LOCK_LEN, 5);
        });
        let ordered = Ordered::decode(&body, &Limits::protocol()).unwrap();
        let op = WireOp::from_ordered(&ordered).unwrap();
        assert_eq!(op.lock_type, Some(1));
        assert_eq!(op.lock_action, Some(0));
        assert_eq!(op.lock_start, Some(10));
        assert_eq!(op.lock_len, Some(5));
    }

    #[test]
    fn to_op_maps_every_creating_and_namespace_class() {
        let state = State::new();

        let mut op = wire_op(OpClass::CREATE_EXCL, "/new");
        op.mode = Some(0o644);
        assert_eq!(
            to_op(&op, None, &state, SESSION).unwrap(),
            Some(Op::CreateFile {
                path: b"/new".to_vec(),
                ino: op.derive_ino(),
                mode: 0o644,
                uid: 11,
                gid: 12,
                mtime_ns: 13,
            })
        );

        let mut op = wire_op(OpClass::MKDIR, "/dir");
        op.mode = Some(0o755);
        assert_eq!(
            to_op(&op, None, &state, SESSION).unwrap(),
            Some(Op::CreateDir {
                path: b"/dir".to_vec(),
                ino: op.derive_ino(),
                mode: 0o755,
                uid: 11,
                gid: 12,
                mtime_ns: 13,
            })
        );

        let mut op = wire_op(OpClass::SYMLINK, "/sym");
        op.target = Some(b"../t".to_vec());
        assert_eq!(
            to_op(&op, None, &state, SESSION).unwrap(),
            Some(Op::Symlink {
                path: b"/sym".to_vec(),
                ino: op.derive_ino(),
                target: b"../t".to_vec(),
                uid: 11,
                gid: 12,
                mtime_ns: 13,
            })
        );

        let mut op = wire_op(OpClass::RENAME, "/f");
        op.path2 = Some("/g".to_owned());
        assert_eq!(
            to_op(&op, None, &state, SESSION).unwrap(),
            Some(Op::Rename {
                from: b"/f".to_vec(),
                to: b"/g".to_vec(),
                mtime_ns: 13,
            })
        );

        let op = wire_op(OpClass::UNLINK, "/f");
        assert_eq!(
            to_op(&op, None, &state, SESSION).unwrap(),
            Some(Op::Unlink {
                path: b"/f".to_vec(),
                mtime_ns: 13,
            })
        );

        let op = wire_op(OpClass::RMDIR, "/d");
        assert_eq!(
            to_op(&op, None, &state, SESSION).unwrap(),
            Some(Op::Rmdir {
                path: b"/d".to_vec(),
                mtime_ns: 13,
            })
        );

        let mut op = wire_op(OpClass::LINK, "/dst");
        op.target = Some(b"/src".to_vec());
        assert_eq!(
            to_op(&op, None, &state, SESSION).unwrap(),
            Some(Op::Link {
                target: b"/src".to_vec(),
                path: b"/dst".to_vec(),
                mtime_ns: 13,
            })
        );

        let mut op = wire_op(OpClass::SETATTR, "/f");
        op.mode = Some(0o600);
        assert_eq!(
            to_op(&op, None, &state, SESSION).unwrap(),
            Some(Op::SetAttr {
                path: b"/f".to_vec(),
                attrs: Attrs {
                    mode: Some(0o600),
                    mtime_ns: Some(13),
                    ..Attrs::default()
                },
                size: None,
                chunks: Vec::new(),
            })
        );

        let mut op = wire_op(OpClass::SETATTR, "/f");
        op.mode = Some(0o600);
        op.mtime_ns = 0;
        assert_eq!(
            to_op(&op, None, &state, SESSION).unwrap(),
            Some(Op::SetAttr {
                path: b"/f".to_vec(),
                attrs: Attrs {
                    mode: Some(0o600),
                    ..Attrs::default()
                },
                size: None,
                chunks: Vec::new(),
            }),
            "a zero timestamp means the client asked to keep the current mtime"
        );
    }

    #[test]
    fn to_op_maps_write_pwrite_and_truncate_to_a_whole_file() {
        let state = state_with_file();
        let data = b"hello";

        let mut op = wire_op(OpClass::WRITE, "/f");
        op.data = Some(DataRef {
            session: SessionId::new(1),
            total_len: 5,
            data_hash: *blake3::hash(data).as_bytes(),
        });
        assert_eq!(
            to_op(&op, Some(data), &state, SESSION).unwrap(),
            Some(Op::Write {
                path: b"/f".to_vec(),
                chunks: chunks_of(data),
                mtime_ns: 13,
            })
        );

        // A patch is already the complete file by the time it reaches here.
        let mut op = wire_op(OpClass::PWRITE, "/f");
        op.offset = Some(2);
        op.data = Some(DataRef {
            session: SessionId::new(2),
            total_len: 3,
            data_hash: *blake3::hash(b"llo").as_bytes(),
        });
        assert_eq!(
            to_op(&op, Some(data), &state, SESSION).unwrap(),
            Some(Op::Write {
                path: b"/f".to_vec(),
                chunks: chunks_of(data),
                mtime_ns: 13,
            })
        );

        let mut op = wire_op(OpClass::TRUNCATE, "/f");
        op.length = Some(3);
        assert_eq!(
            to_op(&op, Some(b"hel"), &state, SESSION).unwrap(),
            Some(Op::Truncate {
                path: b"/f".to_vec(),
                size: 3,
                chunks: chunks_of(b"hel"),
                mtime_ns: 13,
            })
        );

        // A size-changing SETATTR is one operation with one chunk list.
        let mut op = wire_op(OpClass::SETATTR, "/f");
        op.mode = Some(0o600);
        op.length = Some(3);
        assert_eq!(
            to_op(&op, Some(b"hel"), &state, SESSION).unwrap(),
            Some(Op::SetAttr {
                path: b"/f".to_vec(),
                attrs: Attrs {
                    mode: Some(0o600),
                    mtime_ns: Some(13),
                    ..Attrs::default()
                },
                size: Some(3),
                chunks: chunks_of(b"hel"),
            })
        );

        // The store must assemble the content for every write class.
        assert!(to_op(&op, None, &state, SESSION).is_err());
    }

    #[test]
    fn to_op_maps_locks_and_no_op_classes() {
        let state = state_with_file();

        let mut op = wire_op(OpClass::FCNTL_LOCK, "/f");
        op.lock_type = Some(1);
        op.lock_action = Some(LOCK_ACTION_SET);
        op.lock_start = Some(10);
        op.lock_len = Some(5);
        assert_eq!(
            to_op(&op, None, &state, SESSION).unwrap(),
            Some(Op::Lock {
                path: b"/f".to_vec(),
                session: SESSION,
                typ: LockType::Write,
                start: 10,
                end: 14,
            })
        );

        // Length zero means "to end of file".
        op.lock_len = Some(0);
        assert_eq!(
            to_op(&op, None, &state, SESSION).unwrap(),
            Some(Op::Lock {
                path: b"/f".to_vec(),
                session: SESSION,
                typ: LockType::Write,
                start: 10,
                end: u64::MAX,
            })
        );

        op.lock_action = Some(LOCK_ACTION_UNLOCK);
        assert_eq!(
            to_op(&op, None, &state, SESSION).unwrap(),
            Some(Op::Unlock {
                path: b"/f".to_vec(),
                session: SESSION,
                start: 10,
                end: u64::MAX,
            })
        );

        let op = wire_op(OpClass::FLOCK, "/f");
        assert_eq!(to_op(&op, None, &state, SESSION).unwrap(), None);

        let op = wire_op(OpClass::SYNC_CTRL, "/");
        assert_eq!(to_op(&op, None, &state, SESSION).unwrap(), None);

        let op = wire_op(OpClass::LEAVE, "");
        assert_eq!(
            to_op(&op, None, &state, SESSION).unwrap(),
            Some(Op::Leave { session: SESSION })
        );
    }

    #[test]
    fn event_for_records_create_write_and_rename() {
        let create = Op::CreateFile {
            path: b"/f".to_vec(),
            ino: 7,
            mode: 0o644,
            uid: 1,
            gid: 2,
            mtime_ns: 3,
        };
        let mut create_wire = wire_op(OpClass::CREATE_EXCL, "/f");
        create_wire.op_id = 7u128.to_le_bytes();
        let draft = event_for(&create_wire, &create, &State::new(), SESSION);
        assert_eq!(draft.path.as_deref(), Some("/f"));
        assert_eq!(draft.op_id, Some(7u128.to_le_bytes()));
        assert_eq!(
            draft.payload,
            EventPayload::CreateFile {
                ino: 7u128.to_le_bytes(),
                mode: 0o644,
                uid: 1,
                gid: 2,
                mtime_ns: 3,
                file_root: empty_file_root(),
            }
        );
        assert_eq!(draft.validate().unwrap(), EventKind::CreateFile);

        let state = state_with_file();
        let data = b"hello";
        let write_chunks = chunks_of(data);
        let write = Op::Write {
            path: b"/f".to_vec(),
            chunks: write_chunks.clone(),
            mtime_ns: 9,
        };
        let mut write_wire = wire_op(OpClass::WRITE, "/f");
        write_wire.data = Some(DataRef {
            session: SessionId::new(1),
            total_len: 5,
            data_hash: *blake3::hash(data).as_bytes(),
        });
        let draft = event_for(&write_wire, &write, &state, SESSION);
        assert_eq!(
            draft.payload,
            EventPayload::Write {
                ino: 7u128.to_le_bytes(),
                offset: 0,
                len: 5,
                size: 5,
                file_root: file_root(&write_chunks),
                mtime_ns: 9,
                chunks: chunk_refs(&write_chunks),
            }
        );
        assert_eq!(draft.validate().unwrap(), EventKind::Write);

        let rename = Op::Rename {
            from: b"/f".to_vec(),
            to: b"/g".to_vec(),
            mtime_ns: 10,
        };
        let mut rename_wire = wire_op(OpClass::RENAME, "/f");
        rename_wire.path2 = Some("/g".to_owned());
        let draft = event_for(&rename_wire, &rename, &state, SESSION);
        assert_eq!(draft.path.as_deref(), Some("/f"));
        assert_eq!(draft.path2.as_deref(), Some("/g"));
        assert_eq!(
            draft.payload,
            EventPayload::Rename {
                ino: 7u128.to_le_bytes(),
                mtime_ns: Some(10),
            }
        );
        assert_eq!(draft.validate().unwrap(), EventKind::Rename);
    }

    #[test]
    fn event_for_metadata_ops_carry_their_timestamp() {
        let mut state = state_with_file();
        state
            .apply(&Op::CreateDir {
                path: b"/d".to_vec(),
                ino: 8,
                mode: 0o755,
                uid: 1,
                gid: 2,
                mtime_ns: 4,
            })
            .unwrap();

        let unlink = Op::Unlink {
            path: b"/f".to_vec(),
            mtime_ns: 20,
        };
        let draft = event_for(
            &wire_op(OpClass::UNLINK, "/f"),
            &unlink,
            &state,
            SESSION,
        );
        assert_eq!(
            draft.payload,
            EventPayload::Unlink {
                ino: 7u128.to_le_bytes(),
                mtime_ns: Some(20),
            }
        );

        let rmdir = Op::Rmdir {
            path: b"/d".to_vec(),
            mtime_ns: 21,
        };
        let draft = event_for(&wire_op(OpClass::RMDIR, "/d"), &rmdir, &state, SESSION);
        assert_eq!(
            draft.payload,
            EventPayload::Rmdir {
                ino: 8u128.to_le_bytes(),
                mtime_ns: Some(21),
            }
        );

        let link = Op::Link {
            target: b"/f".to_vec(),
            path: b"/g".to_vec(),
            mtime_ns: 22,
        };
        let mut link_wire = wire_op(OpClass::LINK, "/g");
        link_wire.target = Some(b"/f".to_vec());
        let draft = event_for(&link_wire, &link, &state, SESSION);
        assert_eq!(
            draft.payload,
            EventPayload::Link {
                ino: 7u128.to_le_bytes(),
                mtime_ns: Some(22),
            }
        );
    }

    #[test]
    fn event_for_lock_and_leave_attach_the_session() {
        let state = state_with_file();
        let lock = Op::Lock {
            path: b"/f".to_vec(),
            session: SESSION,
            typ: LockType::Write,
            start: 10,
            end: 14,
        };
        let mut lock_wire = wire_op(OpClass::FCNTL_LOCK, "/f");
        lock_wire.lock_start = Some(10);
        lock_wire.lock_len = Some(5);
        let draft = event_for(&lock_wire, &lock, &state, SESSION);
        assert_eq!(draft.session_id, Some(SESSION));
        assert_eq!(
            draft.payload,
            EventPayload::Lock {
                ino: 7u128.to_le_bytes(),
                start: 10,
                len: 5,
                exclusive: true,
            }
        );
        assert_eq!(draft.validate().unwrap(), EventKind::Lock);

        let leave = Op::Leave { session: SESSION };
        let draft = event_for(&wire_op(OpClass::LEAVE, ""), &leave, &state, SESSION);
        assert_eq!(draft.payload, EventPayload::Leave);
        assert_eq!(draft.session_id, Some(SESSION));
        assert_eq!(draft.path, None);
        assert_eq!(draft.validate().unwrap(), EventKind::Leave);
    }

    #[test]
    fn reject_body_is_op_id_errno_and_reason() {
        let body = reject_body(
            [0xab; 16],
            Reject::new(Errno::EEXIST, "name already exists"),
            None,
            512,
        );
        assert_eq!(&body[..16], &[0xab; 16]);
        assert_eq!(&body[16..20], &Errno::EEXIST.raw().to_le_bytes());
        assert_eq!(&body[20..24], &0u32.to_le_bytes());
        assert_eq!(&body[24..], b"name already exists");
        assert_eq!(body.len(), 24 + "name already exists".len());
    }

    #[test]
    fn an_oversized_reject_state_falls_back_to_a_resync_marker() {
        use crate::store::sqlite::{Object, ObjectKind};

        let state = RejectState {
            path: "/big".to_owned(),
            object: Some(Object {
                ino: [7; 16],
                kind: ObjectKind::File,
                mode: 0o644,
                uid: 1000,
                gid: 1000,
                mtime_ns: 1_700_000_000_000_000_000,
                size: 2 * 64 * 1024,
                file_root: [9; 32],
                block_count: 2,
                target: None,
                nlink: 1,
                deleted: false,
                created_seq: 1,
                updated_seq: 2,
            }),
            chunks: vec![
                ChunkRef {
                    chunk_no: 0,
                    hash: [1; 32],
                    offset: 0,
                    len: 64 * 1024,
                },
                ChunkRef {
                    chunk_no: 1,
                    hash: [2; 32],
                    offset: 64 * 1024,
                    len: 64 * 1024,
                },
            ],
            data: vec![vec![0xaa; 64 * 1024], vec![0xbb; 64 * 1024]],
            parent: Some([3; 16]),
            name: Some("big".to_owned()),
        };
        let detail_max = usize::from(Limits::protocol().detail_max);
        let body = reject_body(
            [0xcd; 16],
            Reject::new(Errno::EEXIST, "name already exists"),
            Some(&state),
            detail_max,
        );
        assert!(body.len() <= detail_max, "detail is {} bytes", body.len());
        assert_eq!(&body[..16], &[0xcd; 16]);
        assert_eq!(
            i32::from_le_bytes(body[16..20].try_into().unwrap()),
            Errno::EEXIST.raw()
        );
        assert_eq!(
            u32::from_le_bytes(body[20..24].try_into().unwrap()),
            u32::MAX
        );

        let encoded = crate::protocol::ErrorMessage {
            reason: crate::protocol::TrnReason::Protocol,
            detail: &body,
            session_id: None,
        }
        .encode()
        .unwrap();
        let decoded =
            crate::protocol::ErrorMessage::decode(&encoded, &Limits::protocol()).unwrap();
        assert_eq!(decoded.detail, &body[..]);
    }

    #[test]
    fn replay_ordered_decodes_as_ordered_with_the_payload_in_extra() {
        let ring = ring();
        let event = row(
            EventKind::CreateFile,
            EventPayload::CreateFile {
                ino: 7u128.to_le_bytes(),
                mode: 0o644,
                uid: 1000,
                gid: 1000,
                mtime_ns: 1_700_000_000_000_000_000,
                file_root: empty_file_root(),
            },
            Some("/new"),
            None,
        );
        let frame = replay_ordered(&event, &ring, &nonces()).unwrap();
        let (decoded, plain) = decode_frame(&frame, &ring);
        assert_eq!(decoded.header.msg_type, MsgType::ORDERED);
        assert_eq!(decoded.header.seq, Seq::UNSEQUENCED);
        assert!(decoded.header.flags.contains(Flags::ENC));

        let ordered = Ordered::decode(&plain, &Limits::protocol()).unwrap();
        assert_eq!(ordered.op_class, OpClass::CREATE_EXCL);
        assert_eq!(ordered.path_str(), Some("/new"));
        assert_eq!(ordered.op_id, OpId::from_bytes([0x77; 16]));
        assert_eq!(ordered.attrs.unwrap().uid, 1000);
        assert_eq!(ordered.attrs.unwrap().gid, 1000);
        assert_eq!(
            ordered.fields.get(fid::F_EXTRA),
            Some(event.payload.as_slice())
        );

        // The same ciphertext, one different sequence number.
        let resequenced = with_seq(&frame, Seq(42)).unwrap();
        let (decoded_again, plain_again) = decode_frame(&resequenced, &ring);
        assert_eq!(decoded_again.header.seq, Seq(42));
        assert_eq!(decoded_again.body, decoded.body);
        assert_eq!(plain_again, plain);
    }

    #[test]
    fn replay_of_a_version_1_setattr_carries_no_length() {
        let ring = ring();
        let legacy = crate::store::sqlite::V1_SETATTR_BYTES;
        let event = EventRow {
            seq: 9,
            epoch: 1,
            op_id: Some([0x77; 16]),
            session_id: None,
            kind: EventKind::Setattr,
            path: Some("/f".to_owned()),
            path2: None,
            ino: Some([0x11; 16]),
            payload: legacy.to_vec(),
            result: "ok".to_owned(),
            applied: true,
            created_at: 0,
        };
        let frame = replay_ordered(&event, &ring, &nonces()).unwrap();
        let (decoded, plain) = decode_frame(&frame, &ring);
        assert_eq!(decoded.header.msg_type, MsgType::ORDERED);
        let ordered = Ordered::decode(&plain, &Limits::protocol()).unwrap();
        assert_eq!(ordered.op_class, OpClass::SETATTR);
        assert_eq!(
            ordered.args,
            OpArgs::Setattr {
                mode: Some(0o644),
                size: None,
            },
            "a version-1 setattr must not synthesize a length"
        );
        assert_eq!(
            ordered.fields.get(fid::F_EXTRA),
            Some(&legacy[..]),
            "replay forwards the stored bytes unchanged"
        );
        assert_eq!(
            EventPayload::decode(EventKind::Setattr, &legacy).unwrap(),
            EventPayload::Setattr {
                ino: [0x11; 16],
                mode: Some(0o644),
                uid: Some(1000),
                gid: Some(1001),
                mtime_ns: Some(1_700_000_000_000_000_000),
                size: None,
            }
        );
    }

    #[test]
    fn replay_write_carries_the_stream_length_and_hash() {
        let data = b"hello replay";
        let chunks = chunks_of(data);
        let event = row(
            EventKind::Write,
            EventPayload::Write {
                ino: 7u128.to_le_bytes(),
                offset: 0,
                len: data.len() as u64,
                size: data.len() as u64,
                file_root: file_root(&chunks),
                mtime_ns: 1,
                chunks: chunk_refs(&chunks),
            },
            Some("/f"),
            None,
        );
        let ring = ring();
        let frame = replay_ordered_with_content(&event, &ring, &nonces(), Some(data)).unwrap();
        let (_, plain) = decode_frame(&frame, &ring);
        let ordered = Ordered::decode(&plain, &Limits::protocol()).unwrap();
        let data_ref = ordered.data().unwrap();
        assert_eq!(data_ref.total_len, data.len() as u64);
        assert_eq!(data_ref.data_hash, *blake3::hash(data).as_bytes());
        assert_eq!(data_ref.session, replay_data_session(&event));
        assert_eq!(
            ordered.fields.get(fid::F_EXTRA),
            Some(event.payload.as_slice())
        );

        // Without the bytes the frame still decodes, with payload-derived
        // placeholders.
        let frame = replay_ordered(&event, &ring, &nonces()).unwrap();
        let (_, plain) = decode_frame(&frame, &ring);
        let ordered = Ordered::decode(&plain, &Limits::protocol()).unwrap();
        let data_ref = ordered.data().unwrap();
        assert_eq!(data_ref.total_len, data.len() as u64);
        assert_eq!(
            data_ref.data_hash,
            refs_hash(&chunk_refs(&chunks)),
            "the placeholder hashes the chunk list"
        );
    }

    #[test]
    fn replay_rename_link_and_leave_fill_the_target_fields() {
        let ring = ring();

        let rename = row(
            EventKind::Rename,
            EventPayload::Rename {
                ino: 7u128.to_le_bytes(),
                mtime_ns: Some(7),
            },
            Some("/a"),
            Some("/b"),
        );
        let frame = replay_ordered(&rename, &ring, &nonces()).unwrap();
        let (_, plain) = decode_frame(&frame, &ring);
        let ordered = Ordered::decode(&plain, &Limits::protocol()).unwrap();
        match ordered.args {
            OpArgs::Rename { path2 } => assert_eq!(path2.as_str(), "/b"),
            other => panic!("unexpected args {other:?}"),
        }

        let link = row(
            EventKind::Link,
            EventPayload::Link {
                ino: 7u128.to_le_bytes(),
                mtime_ns: Some(7),
            },
            Some("/new"),
            Some("/existing"),
        );
        let frame = replay_ordered(&link, &ring, &nonces()).unwrap();
        let (_, plain) = decode_frame(&frame, &ring);
        let ordered = Ordered::decode(&plain, &Limits::protocol()).unwrap();
        assert_eq!(ordered.path_str(), Some("/new"));
        match ordered.args {
            OpArgs::Link { target } => assert_eq!(target.as_str(), "/existing"),
            other => panic!("unexpected args {other:?}"),
        }

        let leave = row(EventKind::Leave, EventPayload::Leave, None, None);
        let frame = replay_ordered(&leave, &ring, &nonces()).unwrap();
        let (_, plain) = decode_frame(&frame, &ring);
        let ordered = Ordered::decode(&plain, &Limits::protocol()).unwrap();
        assert_eq!(ordered.op_class, OpClass::LEAVE);
        assert!(ordered.path.is_none());
        assert_eq!(
            ordered.fields.get(fid::F_EXTRA),
            Some(leave.payload.as_slice())
        );
    }

    #[test]
    fn replay_sync_ctrl_uses_the_root_path() {
        let ring = ring();
        let event = row(
            EventKind::SyncCtrl,
            EventPayload::SyncCtrl { code: 0 },
            None,
            None,
        );
        let frame = replay_ordered(&event, &ring, &nonces()).unwrap();
        let (_, plain) = decode_frame(&frame, &ring);
        let ordered = Ordered::decode(&plain, &Limits::protocol()).unwrap();
        assert_eq!(ordered.op_class, OpClass::SYNC_CTRL);
        assert_eq!(ordered.path_str(), Some("/"));
    }

    #[test]
    fn replay_content_assembles_the_write_stream() {
        let data: Vec<u8> = (0..70_000u32).map(|index| index as u8).collect();
        let split = split_chunks(&data);
        let chunks: Vec<Chunk> = split.iter().map(|(chunk, _)| *chunk).collect();
        let event = row(
            EventKind::Write,
            EventPayload::Write {
                ino: 7u128.to_le_bytes(),
                offset: 0,
                len: data.len() as u64,
                size: data.len() as u64,
                file_root: file_root(&chunks),
                mtime_ns: 1,
                chunks: chunk_refs(&chunks),
            },
            Some("/f"),
            None,
        );
        let content = replay_content(&event, |hash| {
            split
                .iter()
                .find(|(chunk, _)| chunk.hash == *hash)
                .map(|(_, bytes)| bytes.clone())
        })
        .unwrap();
        assert_eq!(content.session, replay_data_session(&event));
        assert_eq!(content.total_len, data.len() as u64);
        assert_eq!(content.data, data);

        assert!(
            replay_content(&event, |_| None).is_none(),
            "a missing chunk must not produce a partial stream"
        );

        let create = row(
            EventKind::CreateFile,
            EventPayload::CreateFile {
                ino: 7u128.to_le_bytes(),
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime_ns: 0,
                file_root: empty_file_root(),
            },
            Some("/f"),
            None,
        );
        assert!(replay_content(&create, |_| None).is_none());
    }

    #[test]
    fn with_seq_rejects_incomplete_input() {
        assert!(matches!(
            with_seq(&[0u8; 4], Seq(1)),
            Err(WireError::NotAFrame)
        ));
    }
}
