//! Content-domain identity and sealing: `chunk_id`, `blob_id`, `nonce || ct`.
//!
//! A chunk is identified by its **plaintext** hash and encrypted with a fresh
//! random nonce (49 A3/D-5):
//!
//! ```text
//! chunk_id = BLAKE3(plaintext)                 // logical identity, 32 B
//! nonce    = 96 random bits                    // getrandom, never derived
//! blob     = nonce(12) || ChaCha-Poly1305(enc_key, nonce, aad, plaintext)
//! blob_id  = BLAKE3(blob)                      // physical identity, 32 B
//! aad      = "sm/v1/chunk" || kind u8 || chunk_id 32 B
//!            || plain_len u32 LE || format_ver u8
//! ```
//!
//! The AAD binds `kind`, `chunk_id` and the plaintext length, so a blob cannot
//! be replayed under another domain or another identity. It deliberately does
//! **not** bind a session, stream or file index: the same chunk must stay
//! decryptable across sessions for dedup and resume (43 §5.1).
//!
//! Opening performs both checks required by 43 I2:
//!
//! 1. the Poly1305 tag (with the AAD above) verifies; and
//! 2. `BLAKE3(plaintext) == chunk_id`.
//!
//! No plaintext leaves this module before both succeed.

use std::fmt;

#[cfg(feature = "reduced-round")]
use chacha20poly1305::ChaCha8Poly1305;
#[cfg(not(feature = "reduced-round"))]
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, Nonce};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::store::chunk_store::{BlobId, CHUNK_BYTES, ChunkId, ChunkKind, NONCE_LEN, TAG_LEN};

#[cfg(feature = "reduced-round")]
type ChunkAead = ChaCha8Poly1305;
#[cfg(not(feature = "reduced-round"))]
type ChunkAead = ChaCha20Poly1305;

/// AAD domain separator for content chunks (49 A13).
pub const CHUNK_AAD: &[u8] = b"sm/v1/chunk";
/// Content format version carried in the AAD.
pub const CHUNK_FORMAT_VER: u8 = 1;

/// One freshly sealed chunk.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedChunk {
    /// Plaintext identity.
    pub chunk_id: ChunkId,
    /// Ciphertext identity.
    pub blob_id: BlobId,
    /// `nonce || ciphertext || tag`.
    pub blob: Vec<u8>,
}

impl fmt::Debug for SealedChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedChunk")
            .field("chunk_id", &self.chunk_id)
            .field("blob_id", &self.blob_id)
            .field("blob_len", &self.blob.len())
            .finish()
    }
}

/// Content sealing/opening failures.
#[derive(Debug, Error)]
pub enum ChunkCipherError {
    /// A plaintext larger than one chunk was offered.
    #[error("chunk plaintext too large: {len} bytes > {max}")]
    PlaintextTooLarge {
        /// Offered length.
        len: usize,
        /// Upper bound.
        max: usize,
    },
    /// A blob shorter than a nonce plus a tag.
    #[error("chunk blob too short: {len} bytes")]
    BlobTooShort {
        /// Offered length.
        len: usize,
    },
    /// The AEAD tag did not verify (wrong key, wrong AAD, or tampering).
    #[error("chunk AEAD authentication failed")]
    Aead,
    /// The decrypted plaintext does not hash to the advertised `chunk_id`.
    #[error("chunk plaintext hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// Advertised identity.
        expected: ChunkId,
        /// Recomputed identity.
        actual: ChunkId,
    },
    /// The fixed-size key could not be installed (cannot happen with 32 B).
    #[error("chunk cipher key is invalid")]
    BadKey,
}

/// Content-domain cipher bound to one `enc_key`.
///
/// The key is held in a fixed array and never formatted. Cloning the cipher
/// copies the key; callers should keep one per key ring.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChunkCipher {
    key: [u8; 32],
}

impl fmt::Debug for ChunkCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChunkCipher").finish_non_exhaustive()
    }
}

impl ChunkCipher {
    /// Bind the cipher to a 32-byte content key (the `enc_key` derived by the
    /// key ring).
    pub const fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Encrypt one chunk with a fresh random nonce.
    ///
    /// # Errors
    ///
    /// [`ChunkCipherError::PlaintextTooLarge`] above
    /// [`crate::store::chunk_store::CHUNK_BYTES`].
    pub fn seal(&self, kind: ChunkKind, plaintext: &[u8]) -> Result<SealedChunk, ChunkCipherError> {
        if plaintext.len() > CHUNK_BYTES {
            return Err(ChunkCipherError::PlaintextTooLarge {
                len: plaintext.len(),
                max: CHUNK_BYTES,
            });
        }
        let chunk_id = ChunkId::of_plaintext(plaintext);
        let mut nonce = [0u8; NONCE_LEN];
        rand::fill(&mut nonce[..]);

        let aad = chunk_aad(kind, &chunk_id, plaintext.len());
        let cipher = ChunkAead::new_from_slice(&self.key).map_err(|_| ChunkCipherError::BadKey)?;
        let ciphertext = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| ChunkCipherError::Aead)?;

        let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        let blob_id = BlobId::of_blob(&blob);
        Ok(SealedChunk {
            chunk_id,
            blob_id,
            blob,
        })
    }

    /// Authenticate and decrypt one blob, then verify its plaintext hash.
    ///
    /// The plaintext is returned in a zeroizing buffer.
    ///
    /// # Errors
    ///
    /// [`ChunkCipherError::BlobTooShort`], [`ChunkCipherError::PlaintextTooLarge`],
    /// [`ChunkCipherError::Aead`] for a tag failure, and
    /// [`ChunkCipherError::HashMismatch`] when the plaintext is not the chunk
    /// the caller asked for.
    pub fn open(
        &self,
        kind: ChunkKind,
        chunk_id: &ChunkId,
        blob: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ChunkCipherError> {
        if blob.len() < NONCE_LEN + TAG_LEN {
            return Err(ChunkCipherError::BlobTooShort { len: blob.len() });
        }
        let plain_len = blob.len() - NONCE_LEN - TAG_LEN;
        if plain_len > CHUNK_BYTES {
            return Err(ChunkCipherError::PlaintextTooLarge {
                len: plain_len,
                max: CHUNK_BYTES,
            });
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&blob[..NONCE_LEN]);
        let ciphertext = &blob[NONCE_LEN..];
        let aad = chunk_aad(kind, chunk_id, plain_len);
        let cipher = ChunkAead::new_from_slice(&self.key).map_err(|_| ChunkCipherError::BadKey)?;
        let plaintext = cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| ChunkCipherError::Aead)?;
        let plaintext = Zeroizing::new(plaintext);
        let actual = ChunkId::of_plaintext(&plaintext);
        if actual != *chunk_id {
            return Err(ChunkCipherError::HashMismatch {
                expected: *chunk_id,
                actual,
            });
        }
        Ok(plaintext)
    }
}

/// The exact content AAD (43 §5.1, 49 A3).
fn chunk_aad(kind: ChunkKind, chunk_id: &ChunkId, plain_len: usize) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CHUNK_AAD.len() + 1 + 32 + 4 + 1);
    aad.extend_from_slice(CHUNK_AAD);
    aad.push(kind.wire());
    aad.extend_from_slice(chunk_id.as_bytes());
    aad.extend_from_slice(&(plain_len as u32).to_le_bytes());
    aad.push(CHUNK_FORMAT_VER);
    aad
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    const KEY: [u8; 32] = [0x5a; 32];

    fn cipher() -> ChunkCipher {
        ChunkCipher::new(KEY)
    }

    /// C-29 / 43 I2
    #[test]
    fn u_chunk_seal_open_roundtrip() {
        let cipher = cipher();
        let plaintext = b"the quick brown fox";
        let sealed = cipher
            .seal(ChunkKind::File, plaintext)
            .unwrap_or_else(|err| panic!("seal: {err}"));

        assert_eq!(sealed.chunk_id, ChunkId::of_plaintext(plaintext));
        assert_eq!(sealed.blob_id, BlobId::of_blob(&sealed.blob));
        assert_eq!(sealed.blob.len(), NONCE_LEN + plaintext.len() + TAG_LEN);
        let opened = cipher
            .open(ChunkKind::File, &sealed.chunk_id, &sealed.blob)
            .unwrap_or_else(|err| panic!("open: {err}"));
        assert_eq!(&opened[..], plaintext);
    }

    /// C-29 / 49 A3
    #[test]
    fn u_chunk_same_plaintext_different_blob_same_id() {
        let cipher = cipher();
        let plaintext = b"same bytes";
        let first = cipher.seal(ChunkKind::File, plaintext).unwrap();
        let second = cipher.seal(ChunkKind::File, plaintext).unwrap();

        assert_eq!(first.chunk_id, second.chunk_id);
        assert_ne!(first.blob_id, second.blob_id, "fresh nonce per seal");
        assert_ne!(first.blob, second.blob);
        assert_eq!(
            &cipher
                .open(ChunkKind::File, &second.chunk_id, &second.blob)
                .unwrap()[..],
            plaintext
        );
    }

    /// C-29 / 43 I2
    #[test]
    fn u_chunk_open_rejects_tampered_blob() {
        let cipher = cipher();
        let sealed = cipher.seal(ChunkKind::File, b"tamper me").unwrap();
        let mut blob = sealed.blob.clone();
        let last = blob.len() - 1;
        blob[last] ^= 0x80;
        let err = cipher
            .open(ChunkKind::File, &sealed.chunk_id, &blob)
            .expect_err("tampering must fail");
        assert!(matches!(err, ChunkCipherError::Aead));
    }

    /// C-29 / 43 I2
    #[test]
    fn u_chunk_open_rejects_wrong_chunk_id_or_kind() {
        let cipher = cipher();
        let sealed = cipher.seal(ChunkKind::File, b"identity").unwrap();
        let wrong = ChunkId::of_plaintext(b"another chunk");

        let err = cipher
            .open(ChunkKind::File, &wrong, &sealed.blob)
            .expect_err("AAD binds the chunk id");
        assert!(matches!(err, ChunkCipherError::Aead));

        let err = cipher
            .open(ChunkKind::Snapshot, &sealed.chunk_id, &sealed.blob)
            .expect_err("AAD binds the kind");
        assert!(matches!(err, ChunkCipherError::Aead));
    }

    /// C-29
    #[test]
    fn u_chunk_seal_rejects_oversize_plaintext() {
        let cipher = cipher();
        let plaintext = vec![0u8; CHUNK_BYTES + 1];
        let err = cipher
            .seal(ChunkKind::File, &plaintext)
            .expect_err("oversize must fail");
        assert!(matches!(err, ChunkCipherError::PlaintextTooLarge { .. }));
    }

    /// C-29
    #[test]
    fn u_chunk_accepts_full_chunk() {
        let cipher = cipher();
        let plaintext = vec![0x7fu8; CHUNK_BYTES];
        let sealed = cipher.seal(ChunkKind::Snapshot, &plaintext).unwrap();
        assert_eq!(sealed.blob.len(), NONCE_LEN + CHUNK_BYTES + TAG_LEN);
        assert_eq!(
            &cipher
                .open(ChunkKind::Snapshot, &sealed.chunk_id, &sealed.blob)
                .unwrap()[..],
            &plaintext[..]
        );
    }
}
