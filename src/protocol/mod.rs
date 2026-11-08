//! Wire format: the only place that turns bytes into structures.
//!
//! Sans-io by construction (44 §0): no tokio, hyper, fuser, clock, RNG or
//! global state. Randomness, time and I/O are injected by callers, so golden
//! vectors, property tests and fuzzing run without a network.
//!
//! # Layout
//!
//! ```text
//! header        21 B = magic u8 | ver u8 | type u8 | flags u16
//!                    | req_id u32 | len u32 | seq u64
//! route_prefix  25 B = session_id u128 | stream u8
//!                    | chunk_index u32 | total_chunks u32
//! ctrl_prefix   18 B = applied_seq u64 | epoch_seen u64 | reserved u16
//! ```
//!
//! The widths are asserted at compile time in [`frame`]; the 17 B / 22 B
//! figures in older documents were arithmetic slips (48 §2, 44 D-H/D-F).
//!
//! # Dependency direction
//!
//! ```text
//! errors <- version <- frame <- codec
//! ```
//!
//! `codec` is a leaf. `crypto`, `messages`, `handshake` and `fragment` are
//! owned by other modules and depend on this one, never the other way round.
//! That is why [`ProtocolError`] carries no crypto or WCP variant: each
//! upper layer wraps its own error at its own boundary.

pub mod codec;
pub mod crypto;
pub mod errors;
pub mod fragment;
pub mod frame;
pub mod handshake;
pub mod messages;
pub mod version;

pub use codec::{FrameDecoder, FrameEncoder, FrameReader, FrameRef, FrameWriter, encode_frame};
pub use crypto::{
    HandshakeKeys, KeyRing, PSK_SALT, PSK_SALT_LEN, PskKeyRing, PskSalt, SessionKey,
    WELCOME_PROOF_LEN,
};
pub use errors::{KickReason, ProtocolError, SyncEndReason, TrnReason};
pub use fragment::{
    CHUNK_PLAIN, ChunkSink, Credit, Fragment, FragmentError, FragmentKey, Fragmenter, Progress,
    Reassembler, SessionTable,
};
pub use frame::{
    BodyEncoding, CTRL_PREFIX_LEN, ClientId, CtrlPrefix, Flags, Frame, FrameBuf, FrameHeader,
    HEADER_LEN, Limits, MAGIC, MIN_PLAIN_BODY, MsgType, OpId, Prefix, PrefixKind, ROUTE_PREFIX_LEN,
    RoutePrefix, Seq, SessionId, StreamId,
};
pub use handshake::{
    Accepted, CLIENT_HANDSHAKE_TIMEOUT_MS, ClientHandshake, ClientPhase, HandshakeError,
    HelloInput, MAX_RECENT_NONCES, NONCE_REPLAY_WINDOW_MS, NonceReplayGuard, ServerHandshake,
};
pub use messages::{
    ACCEPT_SEALED_LEN, AUTH_SEALED_LEN, Accept, Ack, Auth, CompactionState, DataRef,
    Error as ErrorMessage, FieldMap, FileAttrs, Flow, Hello, Kick, Leave, Message, MessageError,
    OpArgs, OpClass, OpIdLog, OpIdVerdict, Ordered, PathError, Ping, Pong, Relay, RelaySub,
    ResyncMode, SeqGate, SeqVerdict, StreamData, SyncEnd, WcpError, WcpWriter, Welcome,
    WelcomeLimits, WirePath, decode_plain, decode_sealed,
};
pub use version::{Caps, FrameVer, Negotiated, ProtoVersion, VersionError, WcpVer, negotiate};

/// Protocol ceiling for `len` (prefix plus body): 4 MiB plus 64 KiB.
///
/// A hard ceiling, not a buffer budget. Ingress uses [`INGRESS_FRAME`].
pub const FRAME_MAX: u32 = 4 * 1024 * 1024 + 64 * 1024;

/// Default ingress limit: 128 KiB.
///
/// Deliberately far below [`FRAME_MAX`]: ten thousand connections times
/// 4 MiB would exhaust any server (44 R2).
pub const INGRESS_FRAME: u32 = 128 * 1024;

/// Largest plaintext a single frame may carry.
pub const MAX_PLAINTEXT: u32 = 64 * 1024;

/// AEAD envelope overhead: `alg u8 + kid u8 + nonce 12 + tag 16`.
pub const ENV_OVERHEAD: u32 = 30;

/// Largest chunk count for one stream.
pub const MAX_CHUNKS: u32 = 1 << 20;

/// Largest field count in one WCP body.
pub const MAX_FIELDS: usize = 64;

/// Largest accepted path.
pub const PATH_MAX: usize = 4096;

/// Largest accepted error detail.
pub const DETAIL_MAX: usize = 512;
