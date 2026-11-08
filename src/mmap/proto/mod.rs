//! SMM1 wire format for the `/mm/v1` HTTP surface.
//!
//! This module is the only place that turns SMM1 bytes into structures. It is
//! sans-io: no socket, clock, RNG, database or HTTP type appears here. Time,
//! the master key, the nonce guard and the byte streams are injected.
//!
//! # Layout
//!
//! ```text
//! header   24 B = magic "SMM1" | ver u8 | kind u8 | flags u16
//!                 | meta_len u32 | data_len u64 | reserved u32
//! meta     field*; field = tag u8 | len u32 | value[len]
//! list     count u32 | (record_len u32 | record)*
//! payload  data_len raw bytes, streamed and hashed
//! ```
//!
//! # Layers
//!
//! ```text
//! error <- tag <- field <- types <- messages/upload
//!                      <- header <- stream
//! auth (independent; uses messages and error)
//! instruction (independent payload stream)
//! convert (P1A boundary; uses messages/upload/types)
//! ```
//!
//! # Strictness
//!
//! A decoder never guesses. Unknown kind, version, flag, reserved bit, tag,
//! duplicate tag, wrong width, invalid UTF-8, NUL, unknown enum, list count
//! over cap, trailing byte or contradictory record is an error. The HTTP
//! layer maps [`ProtoError::error_code`] to a status; [`ErrorCode`] carries
//! the stable vocabulary (400/401/404/409/413/422/423/500/503/507).

pub mod auth;
pub mod convert;
pub mod error;
pub mod field;
pub mod header;
pub mod instruction;
pub mod kind;
pub mod limits;
pub mod messages;
pub mod stream;
pub mod tag;
pub mod types;
pub mod upload;

pub use auth::{
    FrameHasher, HEADER_MAC, HEADER_SEQ, HEADER_SESSION, MacParts, SESSION_TTL_MS, SessionGuard,
    SessionKeys, TIMESTAMP_WINDOW_MS, accept_welcome, check_timestamp, derive_hello_key,
    derive_session_key, encode_mac, encode_session_id, hash_meta, hash_payload, hello_proof,
    mac_input, parse_mac, parse_seq, parse_session_id, verify_hello, verify_welcome, welcome_proof,
};
pub use error::{AuthError, ErrorCode, ProtoError};
pub use field::{FieldWriter, Fields, MAX_FIELDS};
pub use header::{FLAGS_NONE, HEADER_LEN, Header, MAGIC, VERSION};
pub use instruction::{Instruction, InstructionReader, InstructionWriter};
pub use kind::Kind;
pub use limits::{
    Limits, MAX_BATCH, MAX_BLOCKS, MAX_DATA, MAX_ENTRIES, MAX_FILE, MAX_META, MAX_RANGE,
};
pub use messages::{
    Checkout, FileData, FileRead, Hello, Message, SignatureRequest, Signatures, Snapshot, Welcome,
    decode_frame, encode_frame,
};
pub use stream::{PayloadDigest, SmmReader, SmmWriter};
pub use types::{
    BatchState, BlockSignature, DirAttrs, Entry, EntryKind, EntryOp, FileSignature, MAX_BLOCK_SIZE,
    MAX_DETAIL, MAX_LITERAL, MAX_NAME, MAX_NAMESPACE, MAX_PATH, MAX_TARGET, MIN_BLOCK_SIZE,
    ManifestEntrySource, ManifestEntryWire, MmBaseWire, PlanAction, PlanItem, SignatureFile,
    SignatureState, UploadMode, check_name, check_namespace, check_path,
};
pub use upload::{
    Aborted, BatchStateMessage, BatchStatus, DirVersion, DirVersionRequest, ErrorBody, LockAcquire,
    LockGranted, LockRelease, LockReleased, LockRenew, LockRenewed, UploadAbort, UploadBegin,
    UploadCommit, UploadPlan, UploadResult,
};

#[cfg(all(test, feature = "mmap-tests"))]
mod tests;
