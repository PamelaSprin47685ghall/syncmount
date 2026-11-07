//! Chunk identity, content sealing, and the verified cache.
//!
//! | module | responsibility |
//! |---|---|
//! | [`id`] | `ChunkId = BLAKE3(plaintext)`, `BlobId = BLAKE3(blob)`, seal/open |
//! | [`store`] | dual verification in front of [`crate::store::chunk_store`] |
//!
//! The storage layer ([`crate::store::chunk_store`]) owns the on-disk layout
//! and the dual index; this module owns the key-dependent half of the contract
//! (43 I2, C-29). A blob is accepted only after both checks pass:
//!
//! 1. `BLAKE3(blob) == blob_id` (physical, no key);
//! 2. `BLAKE3(decrypt(blob)) == chunk_id` (tag + AAD + plaintext hash).
//!
//! The input to this layer is the `(path, chunk_id, blob)` stream from the
//! fetch/rsync workers; it never needs the manifest (W16 boundary).

pub mod id;
pub mod store;

pub use id::{CHUNK_AAD, CHUNK_FORMAT_VER, ChunkCipher, ChunkCipherError, SealedChunk};
pub use store::{VerifiedChunkStore, VerifyError};

pub use crate::store::chunk_store::{
    BLOB_OVERHEAD, BlobId, CHUNK_BYTES, ChunkError, ChunkId, ChunkKind, MAX_BLOB_BYTES, NONCE_LEN,
    PutOutcome, TAG_LEN,
};
