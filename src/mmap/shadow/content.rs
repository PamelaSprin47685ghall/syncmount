//! Content hashing, frozen snapshots and object publication.
//!
//! `file_root` is the 1.0 chunk-list Merkle root over 64 KiB chunks. The same
//! function is used by the server and by the foundation base encoder, so a
//! value computed here is directly comparable with a checkout entry.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

use crate::mmap::base;
use crate::mmap::types::{CHUNK_BYTES, EntryKind, Hash, Ino};
use crate::store::sqlite::ChunkRef;

use super::ShadowError;
use super::layout::ShadowLayout;

/// Hashes of one frozen byte stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentHashes {
    pub size: u64,
    pub file_root: Hash,
    pub content_hash: Hash,
}

impl ContentHashes {
    /// Hashes of an empty regular file.
    pub fn empty() -> Self {
        Self {
            size: 0,
            file_root: base::empty_file_root(),
            content_hash: *blake3::hash(b"").as_bytes(),
        }
    }
}

/// Hash an in-memory file body.
pub fn hash_bytes(bytes: &[u8]) -> ContentHashes {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytes);
    let content_hash = *hasher.finalize().as_bytes();
    let root = chunk_root(bytes);
    ContentHashes {
        size: bytes.len() as u64,
        file_root: root,
        content_hash,
    }
}

/// Hash one open file without loading it into memory.
pub fn hash_reader<R: Read>(mut reader: R) -> io::Result<ContentHashes> {
    let mut chunk = vec![0u8; CHUNK_BYTES as usize];
    let mut chunks = Vec::new();
    let mut whole = blake3::Hasher::new();
    let mut size = 0u64;
    let mut chunk_no = 0u32;
    loop {
        let read = read_full(&mut reader, &mut chunk)?;
        if read == 0 {
            break;
        }
        let data = &chunk[..read];
        whole.update(data);
        chunks.push(ChunkRef {
            chunk_no,
            hash: *blake3::hash(data).as_bytes(),
            offset: u64::from(chunk_no) * u64::from(CHUNK_BYTES),
            len: read as u32,
        });
        size = size.saturating_add(read as u64);
        chunk_no = chunk_no.saturating_add(1);
        if read < chunk.len() {
            break;
        }
    }
    Ok(ContentHashes {
        size,
        file_root: base::file_root(EntryKind::File, None, &chunks),
        content_hash: *whole.finalize().as_bytes(),
    })
}

/// Hash one path.
pub fn hash_file(path: &Path) -> io::Result<ContentHashes> {
    let file = File::open(path)?;
    hash_reader(file)
}

/// Copy `source` into `destination` while hashing exactly the copied bytes.
///
/// The destination is created or truncated. The caller owns synchronization
/// with live writers; this helper never reads the source twice.
pub fn copy_and_hash(source: &mut File, destination: &Path) -> io::Result<ContentHashes> {
    source.seek_to_start()?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut out = File::create(destination)?;
    let mut chunk = vec![0u8; CHUNK_BYTES as usize];
    let mut chunks = Vec::new();
    let mut whole = blake3::Hasher::new();
    let mut size = 0u64;
    let mut chunk_no = 0u32;
    loop {
        let read = read_full(source, &mut chunk)?;
        if read == 0 {
            break;
        }
        let data = &chunk[..read];
        out.write_all(data)?;
        whole.update(data);
        chunks.push(ChunkRef {
            chunk_no,
            hash: *blake3::hash(data).as_bytes(),
            offset: u64::from(chunk_no) * u64::from(CHUNK_BYTES),
            len: read as u32,
        });
        size = size.saturating_add(read as u64);
        chunk_no = chunk_no.saturating_add(1);
        if read < chunk.len() {
            break;
        }
    }
    out.sync_all()?;
    Ok(ContentHashes {
        size,
        file_root: base::file_root(EntryKind::File, None, &chunks),
        content_hash: *whole.finalize().as_bytes(),
    })
}

/// Write one body into a new staging file and return its hashes.
pub fn write_staged(path: &Path, bytes: &[u8]) -> io::Result<ContentHashes> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut out = File::create(path)?;
    out.write_all(bytes)?;
    out.sync_all()?;
    Ok(hash_bytes(bytes))
}

/// Verify a staged body against the server entry.
pub fn verify_bytes(
    bytes: &[u8],
    size: u64,
    file_root: &Hash,
    content_hash: Option<&Hash>,
) -> Result<ContentHashes, ShadowError> {
    if bytes.len() as u64 != size {
        return Err(ShadowError::Invalid("checkout body length mismatch"));
    }
    let hashes = hash_bytes(bytes);
    if hashes.file_root != *file_root {
        return Err(ShadowError::Invalid("checkout file_root mismatch"));
    }
    if let Some(expected) = content_hash {
        if hashes.content_hash != *expected {
            return Err(ShadowError::Invalid("checkout content_hash mismatch"));
        }
    }
    Ok(hashes)
}

/// Publish a staging file as an object version.
///
/// The object directory is created first. A failed rename leaves the staging
/// file intact, so the caller can retry or discard it.
pub fn publish_staged(
    layout: &ShadowLayout,
    ino: &Ino,
    version: u64,
    staged: &Path,
) -> io::Result<()> {
    fs::create_dir_all(layout.object_dir(ino))?;
    fs::rename(staged, layout.object_path(ino, version))
}

fn chunk_root(bytes: &[u8]) -> Hash {
    let mut chunks = Vec::new();
    for (index, chunk) in bytes.chunks(CHUNK_BYTES as usize).enumerate() {
        chunks.push(ChunkRef {
            chunk_no: index as u32,
            hash: *blake3::hash(chunk).as_bytes(),
            offset: index as u64 * u64::from(CHUNK_BYTES),
            len: chunk.len() as u32,
        });
    }
    base::file_root(EntryKind::File, None, &chunks)
}

fn read_full<R: Read>(reader: &mut R, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

trait SeekToStart {
    fn seek_to_start(&mut self) -> io::Result<()>;
}

impl SeekToStart for File {
    fn seek_to_start(&mut self) -> io::Result<()> {
        use std::io::Seek;
        self.seek(std::io::SeekFrom::Start(0))?;
        Ok(())
    }
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    #[test]
    fn empty_file_root_matches_the_foundation_constant() {
        assert_eq!(hash_bytes(b""), ContentHashes::empty());
        assert_eq!(hash_bytes(b"").file_root, base::empty_file_root());
    }

    #[test]
    fn chunk_root_matches_the_foundation_file_root() {
        let data: Vec<u8> = (0..(CHUNK_BYTES as usize * 2 + 17))
            .map(|index| (index % 251) as u8)
            .collect();
        let hashes = hash_bytes(&data);
        let chunks: Vec<ChunkRef> = data
            .chunks(CHUNK_BYTES as usize)
            .enumerate()
            .map(|(index, chunk)| ChunkRef {
                chunk_no: index as u32,
                hash: *blake3::hash(chunk).as_bytes(),
                offset: index as u64 * u64::from(CHUNK_BYTES),
                len: chunk.len() as u32,
            })
            .collect();
        assert_eq!(
            hashes.file_root,
            base::file_root(EntryKind::File, None, &chunks)
        );
        assert_eq!(hashes.content_hash, *blake3::hash(&data).as_bytes());
        assert_eq!(hashes.size, data.len() as u64);
    }

    #[test]
    fn copy_and_hash_is_byte_exact() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("source");
        let mut source = File::create(&source_path).unwrap();
        let data: Vec<u8> = (0..200_000).map(|index| (index % 239) as u8).collect();
        source.write_all(&data).unwrap();
        drop(source);

        let mut source = File::open(&source_path).unwrap();
        let staged = dir.path().join("stage");
        let hashes = copy_and_hash(&mut source, &staged).unwrap();
        assert_eq!(hashes, hash_bytes(&data));
        assert_eq!(std::fs::read(&staged).unwrap(), data);
    }

    #[test]
    fn verify_rejects_wrong_size_root_and_hash() {
        let hashes = hash_bytes(b"hello");
        verify_bytes(b"hello", 5, &hashes.file_root, Some(&hashes.content_hash)).unwrap();
        assert!(verify_bytes(b"hell", 5, &hashes.file_root, None).is_err());
        assert!(verify_bytes(b"hello", 5, &[0; 32], None).is_err());
        assert!(verify_bytes(b"hello", 5, &hashes.file_root, Some(&[0; 32])).is_err());
    }
}
