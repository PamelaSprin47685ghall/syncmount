//! BLAKE3 checksums.
//!
//! Two widths are used:
//!
//! * [`strong128`] — the first 16 bytes of BLAKE3. It confirms a block after a
//!   weak-checksum hit.
//! * [`file_hash`] — the full 32-byte BLAKE3 of a whole file. It is the final
//!   authority before a file is accepted.

use std::io::{self, Read};

use super::engine::{CHUNK_BYTES, RsyncError};

/// BLAKE3-128 block confirmation.
pub type StrongHash = [u8; 16];

/// BLAKE3-256 whole-file or Merkle-root hash.
pub type Hash256 = [u8; 32];

/// Number of bytes in a strong block hash.
pub const STRONG_LEN: usize = 16;

/// BLAKE3-128 of `bytes`.
#[must_use]
pub fn strong128(bytes: &[u8]) -> StrongHash {
    let hash = blake3::hash(bytes);
    let mut out = [0u8; STRONG_LEN];
    out.copy_from_slice(&hash.as_bytes()[..STRONG_LEN]);
    out
}

/// BLAKE3-256 of `bytes`.
#[must_use]
pub fn file_hash(bytes: &[u8]) -> Hash256 {
    *blake3::hash(bytes).as_bytes()
}

/// Hash a reader and return `(length, BLAKE3-256)`.
pub fn hash_reader<R: Read>(mut reader: R) -> Result<(u64, Hash256), RsyncError> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; CHUNK_BYTES];
    let mut total = 0u64;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                total = total
                    .checked_add(read as u64)
                    .ok_or(RsyncError::SegmentTooLarge {
                        len: u64::MAX,
                        max: u64::MAX,
                    })?;
                hasher.update(&buffer[..read]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(RsyncError::Io(error)),
        }
    }
    Ok((total, *hasher.finalize().as_bytes()))
}

/// BLAKE3-256 of a reader.
pub fn file_hash_reader<R: Read>(reader: R) -> Result<Hash256, RsyncError> {
    Ok(hash_reader(reader)?.1)
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut out, "{byte:02x}").unwrap();
        }
        out
    }

    #[test]
    fn u_rsync_blake3_known_vectors() {
        let cases: &[(&[u8], &str, &str)] = &[
            (
                b"",
                "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
                "af1349b9f5f9a1a6a0404dea36dcc949",
            ),
            (
                b"abc",
                "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
                "6437b3ac38465133ffb63b75273a8db5",
            ),
            (
                b"hello",
                "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f",
                "ea8f163db38682925e4491c5e58d4bb3",
            ),
        ];
        for (input, full, short) in cases {
            assert_eq!(hex(&file_hash(input)), *full, "input={input:02x?}");
            assert_eq!(hex(&strong128(input)), *short, "input={input:02x?}");
        }

        let zeros = vec![0u8; 64 * 1024];
        assert_eq!(
            hex(&file_hash(&zeros)),
            "3bdeaf8f8e98780b318106aafdc3ca257f73df123d97b69112b26044c91a7d56"
        );
        assert_eq!(hex(&strong128(&zeros)), "3bdeaf8f8e98780b318106aafdc3ca25");

        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(
            hex(&file_hash(&bytes)),
            "4a495ba42461748eca8fdad618f976aa726cc2903de9fcb40735a786ac1c196b"
        );
        assert_eq!(hex(&strong128(&bytes)), "4a495ba42461748eca8fdad618f976aa");
    }

    #[test]
    fn u_rsync_file_hash_reader_matches_slice() {
        let data: Vec<u8> = (0..100_000).map(|index| (index % 251) as u8).collect();
        let mut reader = io::Cursor::new(&data);
        assert_eq!(file_hash_reader(&mut reader).unwrap(), file_hash(&data));
    }
}
