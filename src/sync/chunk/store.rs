//! Verified chunk facade: physical hash + plaintext hash, then the cache.
//!
//! [`ChunkStore`] alone can only prove `BLAKE3(blob) == blob_id`; it does not
//! hold a key. This facade adds the second, mandatory check from 43 I2:
//!
//! ```text
//! blob_id == BLAKE3(blob)                      (before decrypt)
//! chunk_id == BLAKE3(open(blob))               (after decrypt)
//! ```
//!
//! Network blobs enter the cache only through [`VerifiedChunkStore::put_blob`];
//! local plaintext enters through [`VerifiedChunkStore::put_plaintext`], which
//! seals first. Reads decrypt and re-verify, so a corrupted cache entry is an
//! error rather than silently returned bytes.

use std::fmt;
use std::sync::Arc;

use thiserror::Error;
use zeroize::Zeroizing;

use crate::store::RootFd;
use crate::store::chunk_store::{BlobId, ChunkError, ChunkId, ChunkKind, ChunkStore, PutOutcome};

use super::id::{ChunkCipher, ChunkCipherError};

/// Dual-verification failures.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// The physical cache rejected the blob.
    #[error(transparent)]
    Store(#[from] ChunkError),
    /// The content cipher rejected the blob or plaintext.
    #[error(transparent)]
    Cipher(#[from] ChunkCipherError),
}

/// A chunk cache that verifies both identities.
#[derive(Debug)]
pub struct VerifiedChunkStore {
    disk: ChunkStore,
    cipher: ChunkCipher,
}

impl VerifiedChunkStore {
    /// Open the cache below `root` and bind it to `enc_key`.
    pub fn open(root: Arc<RootFd>, enc_key: [u8; 32]) -> Result<Self, VerifyError> {
        Ok(Self {
            disk: ChunkStore::open(root)?,
            cipher: ChunkCipher::new(enc_key),
        })
    }

    /// The underlying disk cache (diagnostics, eviction accounting).
    pub fn disk(&self) -> &ChunkStore {
        &self.disk
    }

    /// The content cipher (tests and re-sealing).
    pub fn cipher(&self) -> &ChunkCipher {
        &self.cipher
    }

    /// Seal plaintext and store the blob.
    ///
    /// Returns the `chunk_id` and whether the blob was new.
    pub fn put_plaintext(
        &self,
        kind: ChunkKind,
        plaintext: &[u8],
    ) -> Result<(ChunkId, PutOutcome), VerifyError> {
        let sealed = self.cipher.seal(kind, plaintext)?;
        let outcome = self
            .disk
            .put(kind, &sealed.chunk_id, &sealed.blob, sealed.blob_id)?;
        Ok((sealed.chunk_id, outcome))
    }

    /// Verify a blob received from the network, then store it.
    ///
    /// The caller supplies the identity from the manifest/`BLOCK_REQ`; a blob
    /// that authenticates under a different `chunk_id` is rejected before it
    /// can reach the cache or staging.
    pub fn put_blob(
        &self,
        kind: ChunkKind,
        chunk_id: &ChunkId,
        blob: &[u8],
    ) -> Result<PutOutcome, VerifyError> {
        // Check 1: the physical hash, computed here rather than trusted.
        let blob_id = BlobId::of_blob(blob);
        // Check 2: tag + AAD + plaintext hash. `open` is the only path that
        // produces plaintext, and it verifies before returning.
        self.cipher.open(kind, chunk_id, blob)?;
        Ok(self.disk.put(kind, chunk_id, blob, blob_id)?)
    }

    /// Read and decrypt one chunk.
    ///
    /// `Ok(None)` means "not cached"; `Err` means "cached but corrupt".
    pub fn get(
        &self,
        kind: ChunkKind,
        chunk_id: &ChunkId,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, VerifyError> {
        let Some(blob) = self.disk.get(kind, chunk_id)? else {
            return Ok(None);
        };
        Ok(Some(self.cipher.open(kind, chunk_id, &blob)?))
    }

    /// Read one raw blob, verifying its physical hash.
    pub fn get_blob(
        &self,
        kind: ChunkKind,
        chunk_id: &ChunkId,
    ) -> Result<Option<Vec<u8>>, VerifyError> {
        Ok(self.disk.get(kind, chunk_id)?)
    }

    /// Cache presence.
    pub fn has(&self, kind: ChunkKind, chunk_id: &ChunkId) -> bool {
        self.disk.has(kind, chunk_id)
    }

    /// Remove one chunk.
    pub fn evict(&self, kind: ChunkKind, chunk_id: &ChunkId) -> Result<bool, VerifyError> {
        Ok(self.disk.evict(kind, chunk_id)?)
    }

    /// Total cached bytes.
    pub fn bytes(&self) -> u64 {
        self.disk.bytes()
    }

    /// Stored blob id for a chunk, when known.
    pub fn blob_id_of(&self, kind: ChunkKind, chunk_id: &ChunkId) -> Option<BlobId> {
        self.disk.blob_id_of(kind, chunk_id)
    }

    /// Cached chunk id for a blob, when known.
    pub fn chunk_id_of_blob(&self, blob_id: &BlobId) -> Option<ChunkId> {
        self.disk.chunk_id_of_blob(blob_id)
    }
}

impl fmt::Display for VerifiedChunkStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifiedChunkStore({} chunks)", self.disk.len())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::store::RootFd;
    use crate::store::chunk_store::{BLOB_OVERHEAD, CHUNK_BYTES};
    use std::sync::Arc;
    use tempfile::TempDir;

    const KEY: [u8; 32] = [0x31; 32];

    fn setup(tag: &str) -> (TempDir, VerifiedChunkStore) {
        let tmp = TempDir::new().unwrap_or_else(|err| panic!("tempdir {tag}: {err}"));
        let mount = tmp.path().join("mnt");
        std::fs::create_dir(&mount).unwrap_or_else(|err| panic!("mkdir {tag}: {err}"));
        let root = Arc::new(
            RootFd::open_before_mount(&mount).unwrap_or_else(|err| panic!("root {tag}: {err}")),
        );
        let store =
            VerifiedChunkStore::open(root, KEY).unwrap_or_else(|err| panic!("open {tag}: {err}"));
        (tmp, store)
    }

    /// C-29 / 43 I2
    #[test]
    fn u_chunk_verified_put_get_dual_check() {
        let (_tmp, store) = setup("verified");
        let plaintext = b"verified plaintext";
        let (id, outcome) = store
            .put_plaintext(ChunkKind::File, plaintext)
            .unwrap_or_else(|err| panic!("put: {err}"));
        assert_eq!(outcome, PutOutcome::Stored);
        assert_eq!(id, ChunkId::of_plaintext(plaintext));
        assert!(store.has(ChunkKind::File, &id));

        let blob = store
            .get_blob(ChunkKind::File, &id)
            .unwrap()
            .unwrap_or_else(|| panic!("blob missing"));
        assert_eq!(blob.len(), plaintext.len() + BLOB_OVERHEAD);
        assert_eq!(
            store.blob_id_of(ChunkKind::File, &id),
            Some(BlobId::of_blob(&blob))
        );

        let opened = store
            .get(ChunkKind::File, &id)
            .unwrap()
            .unwrap_or_else(|| panic!("plaintext missing"));
        assert_eq!(&opened[..], plaintext);
    }

    /// C-29 / 43 I2
    #[test]
    fn u_chunk_verified_rejects_bad_plaintext_identity() {
        let (_tmp, store) = setup("bad-id");
        let sealed = store
            .cipher()
            .seal(ChunkKind::File, b"actual plaintext")
            .unwrap();
        let wrong = ChunkId::of_plaintext(b"claimed plaintext");

        let err = store
            .put_blob(ChunkKind::File, &wrong, &sealed.blob)
            .expect_err("wrong chunk id must fail");
        assert!(matches!(err, VerifyError::Cipher(ChunkCipherError::Aead)));
        assert!(!store.has(ChunkKind::File, &wrong));
        assert_eq!(store.bytes(), 0);
    }

    /// C-29 / 43 I2
    #[test]
    fn u_chunk_verified_rejects_tampered_blob() {
        let (_tmp, store) = setup("tamper");
        let sealed = store.cipher().seal(ChunkKind::File, b"integrity").unwrap();
        let mut blob = sealed.blob.clone();
        blob[BLOB_OVERHEAD] ^= 0x01;

        let err = store
            .put_blob(ChunkKind::File, &sealed.chunk_id, &blob)
            .expect_err("tampered blob must fail");
        assert!(matches!(err, VerifyError::Cipher(ChunkCipherError::Aead)));
        assert!(!store.has(ChunkKind::File, &sealed.chunk_id));
    }

    /// C-29 / 49 A3
    #[test]
    fn u_chunk_verified_dedup_same_plaintext() {
        let (_tmp, store) = setup("dedup");
        let plaintext = b"same chunk";
        let (id, first) = store.put_plaintext(ChunkKind::File, plaintext).unwrap();
        let (id_again, second) = store.put_plaintext(ChunkKind::File, plaintext).unwrap();

        assert_eq!(id, id_again);
        assert_eq!(first, PutOutcome::Stored);
        assert!(matches!(second, PutOutcome::Duplicate { .. }));
        assert_eq!(store.disk().len(), 1);
        assert_eq!(
            store.bytes(),
            (plaintext.len() + BLOB_OVERHEAD) as u64,
            "a duplicate must not grow the cache"
        );
    }

    /// C-29 / 49 A3
    #[test]
    fn u_chunk_same_plaintext_different_blob_same_id() {
        let (_tmp, store) = setup("nonce");
        let plaintext = b"deterministic id, random nonce";
        let first = store.cipher().seal(ChunkKind::File, plaintext).unwrap();
        let second = store.cipher().seal(ChunkKind::File, plaintext).unwrap();

        assert_eq!(first.chunk_id, second.chunk_id);
        assert_ne!(first.blob_id, second.blob_id);

        assert_eq!(
            store
                .put_blob(ChunkKind::File, &first.chunk_id, &first.blob)
                .unwrap(),
            PutOutcome::Stored
        );
        assert_eq!(
            store
                .put_blob(ChunkKind::File, &second.chunk_id, &second.blob)
                .unwrap(),
            PutOutcome::Duplicate {
                existing: first.blob_id
            }
        );

        assert_eq!(store.disk().len(), 1);
        assert_eq!(
            store.blob_id_of(ChunkKind::File, &first.chunk_id),
            Some(first.blob_id)
        );
        assert_eq!(store.chunk_id_of_blob(&second.blob_id), None);
        assert_eq!(
            &store
                .get(ChunkKind::File, &first.chunk_id)
                .unwrap()
                .unwrap()[..],
            plaintext
        );
    }

    /// C-29
    #[test]
    fn u_chunk_verified_detects_disk_corruption() {
        let (_tmp, store) = setup("corrupt");
        let (id, _) = store
            .put_plaintext(ChunkKind::Snapshot, b"on disk")
            .unwrap();
        let path = ChunkStore::blob_path(ChunkKind::Snapshot, &id);
        let fd = store
            .disk()
            .root()
            .open_at(&path, rustix::fs::OFlags::WRONLY, rustix::fs::Mode::empty())
            .unwrap();
        rustix::io::pwrite(&fd, &[0xff], 0).unwrap();
        drop(fd);

        let err = store
            .get(ChunkKind::Snapshot, &id)
            .expect_err("corruption must be reported");
        assert!(matches!(
            err,
            VerifyError::Store(ChunkError::BlobIdMismatch { .. })
        ));
    }

    /// C-29
    #[test]
    fn u_chunk_verified_evicts() {
        let (_tmp, store) = setup("evict");
        let (id, _) = store.put_plaintext(ChunkKind::Delta, b"evict me").unwrap();
        assert!(store.evict(ChunkKind::Delta, &id).unwrap());
        assert!(!store.has(ChunkKind::Delta, &id));
        assert_eq!(store.bytes(), 0);
    }

    /// C-29
    #[test]
    fn u_chunk_verified_full_chunk_boundary() {
        let (_tmp, store) = setup("boundary");
        let plaintext = vec![0x42u8; CHUNK_BYTES];
        let (id, _) = store.put_plaintext(ChunkKind::File, &plaintext).unwrap();
        let opened = store.get(ChunkKind::File, &id).unwrap().unwrap();
        assert_eq!(&opened[..], &plaintext[..]);
    }
}
