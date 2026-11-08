//! Field tags for the SMM1 meta stream.
//!
//! Tags `0x01..=0x40` are the design table. Tags `0x41..=0x4A` fill gaps the
//! table left open (request `bodies`, signature file lists, conditional
//! versions, plan actions and error diagnostics). The numbers are wire
//! contract: append only, never reuse.
//!
//! Nested field streams (`limits`, `dir_attrs`) use their own tag space; a tag
//! number means what the *enclosing record* says it means. Records are
//! self-delimiting, so the two spaces never meet.

// --- 0x01..=0x40: the design table -----------------------------------------

/// Protocol version carried inside a record (`u16`).
pub const VER: u8 = 0x01;
/// Namespace (`string`).
pub const NAMESPACE: u8 = 0x02;
/// Canonical directory path (`string`).
pub const DIR_PATH: u8 = 0x03;
/// Directory inode (16 B).
pub const DIR_INO: u8 = 0x04;
/// Directory version (32 B).
pub const DIR_VERSION: u8 = 0x05;
/// Per-directory `dir_seq` (`u64`).
pub const BASE_SEQ: u8 = 0x06;
/// Global `mm_seq` (`u64`).
pub const SNAPSHOT_SEQ: u8 = 0x07;
/// Database epoch (`u64`).
pub const EPOCH: u8 = 0x08;
/// Client id (16 B).
pub const CLIENT_ID: u8 = 0x09;
/// Session id (16 B).
pub const SESSION_ID: u8 = 0x0A;
/// Lock id (16 B).
pub const LOCK_ID: u8 = 0x0B;
/// Batch id (16 B).
pub const BATCH_ID: u8 = 0x0C;
/// Absolute lease deadline (`u64`).
pub const EXPIRES_AT_MS: u8 = 0x0D;
/// Lease duration (`u32`).
pub const TTL_MS: u8 = 0x0E;
/// Canonical manifest hash (32 B).
pub const MANIFEST_HASH: u8 = 0x0F;
/// Number of direct entries (`u32`).
pub const ENTRY_COUNT: u8 = 0x10;
/// Direct-entry list.
pub const ENTRIES: u8 = 0x11;
/// Entry name (`string`).
pub const NAME: u8 = 0x12;
/// Inode (16 B).
pub const INO: u8 = 0x13;
/// Entry kind (`u8`).
pub const ENTRY_KIND: u8 = 0x14;
/// Entry or plan operation (`u8`).
pub const OP: u8 = 0x15;
/// Rename source name (`string`).
pub const FROM_NAME: u8 = 0x16;
/// Permission bits (`u32`).
pub const MODE: u8 = 0x17;
/// Owner uid (`u32`).
pub const UID: u8 = 0x18;
/// Owner gid (`u32`).
pub const GID: u8 = 0x19;
/// Modification time (`u64`).
pub const MTIME_NS: u8 = 0x1A;
/// Size in bytes (`u64`).
pub const SIZE: u8 = 0x1B;
/// Whole-file BLAKE3 (32 B).
pub const CONTENT_HASH: u8 = 0x1C;
/// Symlink target bytes.
pub const TARGET: u8 = 0x1D;
/// rsync block size (`u32`).
pub const BLOCK_SIZE: u8 = 0x1E;
/// rsync block count (`u32`).
pub const BLOCK_COUNT: u8 = 0x1F;
/// Block signature list.
pub const BLOCKS: u8 = 0x20;
/// rsync weak checksum (`u32`).
pub const WEAK: u8 = 0x21;
/// rsync strong checksum (32 B).
pub const STRONG: u8 = 0x22;
/// Block length (`u32`).
pub const BLOCK_LEN: u8 = 0x23;
/// Instruction opcode (`u8`).
pub const INSTRUCTION: u8 = 0x24;
/// Manifest file index (`u32`).
pub const FILE_INDEX: u8 = 0x25;
/// Base block index (`u32`).
pub const BLOCK_INDEX: u8 = 0x26;
/// Literal byte count (`u32`).
pub const LITERAL_LEN: u8 = 0x27;
/// Wire error code (`u16`).
pub const ERROR_CODE: u8 = 0x28;
/// Human-readable detail (`string`).
pub const DETAIL: u8 = 0x29;
/// Ask for a full retry (`u8`).
pub const RETRY_FULL: u8 = 0x2A;
/// Lock owner client id (16 B).
pub const OWNER_CLIENT: u8 = 0x2B;
/// Current global sequence (`u64`).
pub const CURRENT_SNAPSHOT_SEQ: u8 = 0x2C;
/// Batch state (`u8`).
pub const BATCH_STATE: u8 = 0x2D;
/// Directory version after commit (32 B).
pub const DIR_VERSION_AFTER: u8 = 0x2E;
/// Bytes acknowledged as uploaded (`u64`).
pub const PROGRESS_BYTES: u8 = 0x2F;
/// Range start (`u64`).
pub const RANGE_OFFSET: u8 = 0x30;
/// Range length (`u32`).
pub const RANGE_LEN: u8 = 0x31;
/// Client nonce (32 B).
pub const CLIENT_NONCE: u8 = 0x32;
/// Server nonce (32 B).
pub const SERVER_NONCE: u8 = 0x33;
/// Client clock (`u64`).
pub const TIMESTAMP_MS: u8 = 0x34;
/// Keyed proof (32 B).
pub const PROOF: u8 = 0x35;
/// Session deadline (`u64`).
pub const SESSION_EXPIRES_AT_MS: u8 = 0x36;
/// Nested [`super::types::Limits`].
pub const LIMITS: u8 = 0x37;
/// Nested [`super::types::DirAttrs`].
pub const DIR_ATTRS: u8 = 0x38;
/// Structural (directory) entry list.
pub const STRUCTURAL: u8 = 0x39;
/// 64 KiB-chunk Merkle root (32 B).
pub const FILE_ROOT: u8 = 0x3A;
/// BLAKE3 of one byte range (32 B).
pub const RANGE_HASH: u8 = 0x3B;
/// Per-directory sequence after commit (`u64`).
pub const BASE_SEQ_AFTER: u8 = 0x3C;
/// Committed byte count (`u64`).
pub const BYTES: u8 = 0x3D;
/// Commit time (`u64`).
pub const COMMITTED_AT_MS: u8 = 0x3E;
/// Missing entry names.
pub const MISSING: u8 = 0x3F;
/// The base sequence the client asked for (`u64`).
pub const REQUEST_BASE_SEQ: u8 = 0x40;

// --- 0x41..=0x4A: gaps filled by this implementation -----------------------

/// `0` manifest only, `1` manifest plus bodies (`u8`).
pub const BODIES: u8 = 0x41;
/// Signature request/response file list.
pub const FILES: u8 = 0x42;
/// Conditional checkout on a directory version (32 B).
pub const IF_DIR_VERSION: u8 = 0x43;
/// Conditional checkout on a global snapshot (`u64`).
pub const IF_SNAPSHOT_SEQ: u8 = 0x44;
/// Signature state (`u8`).
pub const SIGNATURE_STATE: u8 = 0x45;
/// Upload plan list.
pub const PLAN: u8 = 0x46;
/// Expected hash in a mismatch error (32 B).
pub const EXPECTED: u8 = 0x47;
/// Actual hash in a mismatch error (32 B).
pub const ACTUAL: u8 = 0x48;
/// Retry hint in milliseconds (`u64`).
pub const RETRY_AFTER_MS: u8 = 0x49;
/// Free-form reason (`string`).
pub const REASON: u8 = 0x4A;

// --- Nested `limits` tag space ---------------------------------------------

/// Nested limits: direct-entry cap.
pub const LIMIT_MAX_ENTRIES: u8 = 0x01;
/// Nested limits: block cap.
pub const LIMIT_MAX_BLOCKS: u8 = 0x02;
/// Nested limits: meta cap.
pub const LIMIT_MAX_META_LEN: u8 = 0x03;
/// Nested limits: payload cap.
pub const LIMIT_MAX_DATA_LEN: u8 = 0x04;
/// Nested limits: one `FILE_READ` range.
pub const LIMIT_MAX_RANGE_LEN: u8 = 0x05;
/// Nested limits: one file.
pub const LIMIT_MAX_FILE_SIZE: u8 = 0x06;
/// Nested limits: one batch.
pub const LIMIT_MAX_BATCH_BYTES: u8 = 0x07;

/// All tags this version defines. A decoder still checks each record's own
/// allowed set; this list only bounds the tag byte.
pub const MAX_TAG: u8 = REASON;
