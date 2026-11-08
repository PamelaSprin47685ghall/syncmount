//! Whole-file verification.

use std::io::Read;

use super::engine::RsyncError;
use super::strong::{Hash256, file_hash};

pub use super::strong::hash_reader;

/// Check the length and BLAKE3-256 of `bytes`.
#[must_use]
pub fn verify(bytes: &[u8], size: u64, hash: &Hash256) -> bool {
    bytes.len() as u64 == size && file_hash(bytes) == *hash
}

/// Stream a reader and compare its length and BLAKE3-256.
pub fn verify_reader<R: Read>(reader: R, size: u64, hash: &Hash256) -> Result<bool, RsyncError> {
    let (actual_size, actual_hash) = hash_reader(reader)?;
    Ok(actual_size == size && actual_hash == *hash)
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::io::Cursor;

    #[test]
    fn u_rsync_verify_accepts_matching_length_and_hash() {
        let data = b"hello world";
        let hash = file_hash(data);
        assert!(verify(data, data.len() as u64, &hash));
        assert!(!verify(data, data.len() as u64 + 1, &hash));
        assert!(!verify(data, data.len() as u64, &[0u8; 32]));
    }

    #[test]
    fn u_rsync_verify_reader_matches_slice() {
        let data = vec![0x5au8; 100_000];
        let hash = file_hash(&data);
        assert!(verify_reader(Cursor::new(&data), data.len() as u64, &hash).unwrap());
        assert!(!verify_reader(Cursor::new(&data), 1, &hash).unwrap());
        assert!(!verify_reader(Cursor::new(&data), data.len() as u64, &[0u8; 32]).unwrap());
    }
}
