//! Per-batch spool: manifest record, reconstructed files and temporary
//! request payloads.
//!
//! ```text
//! {spool}/batches/{batch_id}/begin.bin     bincode BeginRecord
//! {spool}/batches/{batch_id}/files/{i}.bin one reconstructed file
//! {spool}/tmp/{random}.bin                 one commit instruction stream
//! ```
//!
//! The batch id is client-supplied but always encoded as lower-case hex, so it
//! can never escape the spool root. A batch directory is removed only after the
//! commit is durable or the batch is aborted.

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::mmap::proto::{ErrorCode, UploadMode};
use crate::mmap::types::{BatchId, DirAttrs, ManifestEntry};

use super::{BATCH_DIR, Fault, TMP_DIR};

/// The begin manifest saved for the commit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BeginRecord {
    /// Final manifest entries. Missing client inodes have been assigned.
    pub entries: Vec<ManifestEntry>,
    /// Attributes of the directory itself.
    pub dir_attrs: DirAttrs,
    /// Delta or full, stored as the wire value.
    pub mode: u8,
}

impl BeginRecord {
    /// The upload mode this record was begun with.
    pub fn mode(&self) -> Result<UploadMode, Fault> {
        UploadMode::from_u32(u32::from(self.mode)).map_err(Fault::from)
    }
}

/// One spool root.
#[derive(Clone, Debug)]
pub struct Spool {
    root: PathBuf,
}

impl Spool {
    /// Create the spool root and its fixed subdirectories.
    pub fn open(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join(BATCH_DIR))?;
        fs::create_dir_all(root.join(TMP_DIR))?;
        Ok(Self { root })
    }

    /// A fresh unique temporary path. The file is not created.
    pub fn tmp_path(&self) -> PathBuf {
        loop {
            let path = self
                .root
                .join(TMP_DIR)
                .join(format!("{}.bin", hex::encode(rand::random::<[u8; 16]>())));
            if !path.exists() {
                return path;
            }
        }
    }

    /// One batch directory.
    pub fn batch_dir(&self, batch_id: BatchId) -> PathBuf {
        self.root.join(BATCH_DIR).join(batch_id.to_hex())
    }

    /// One batch's begin record.
    pub fn begin_path(&self, batch_id: BatchId) -> PathBuf {
        self.batch_dir(batch_id).join("begin.bin")
    }

    /// One batch's reconstructed-file directory.
    pub fn files_dir(&self, batch_id: BatchId) -> PathBuf {
        self.batch_dir(batch_id).join("files")
    }

    /// One reconstructed file.
    pub fn file_path(&self, batch_id: BatchId, index: usize) -> PathBuf {
        self.files_dir(batch_id).join(format!("{index}.bin"))
    }

    /// Create (or reset) one batch directory.
    pub fn create_batch(&self, batch_id: BatchId) -> io::Result<()> {
        let dir = self.batch_dir(batch_id);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        fs::create_dir_all(dir.join("files"))?;
        Ok(())
    }

    /// Write the begin record atomically.
    pub fn write_begin(&self, batch_id: BatchId, record: &BeginRecord) -> Result<(), Fault> {
        let bytes = encode_begin(record)?;
        let path = self.begin_path(batch_id);
        let tmp = path.with_extension("bin.tmp");
        {
            let file = File::create(&tmp)?;
            let mut writer = BufWriter::new(file);
            writer.write_all(&bytes)?;
            writer.flush()?;
            writer.get_ref().sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Read the begin record.
    pub fn read_begin(&self, batch_id: BatchId) -> Result<BeginRecord, Fault> {
        let path = self.begin_path(batch_id);
        let file = File::open(&path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                Fault::detail(ErrorCode::BatchNotFound, "batch spool is missing")
            } else {
                Fault::from(error)
            }
        })?;
        let mut bytes = Vec::new();
        BufReader::new(file).read_to_end(&mut bytes)?;
        decode_begin(&bytes)
    }

    /// Remove one batch directory. Missing is not an error.
    pub fn remove_batch(&self, batch_id: BatchId) {
        let _ = fs::remove_dir_all(self.batch_dir(batch_id));
    }

    /// Remove a spool path returned by a database row.
    pub fn remove_path(&self, path: &str) {
        let path = Path::new(path);
        if path.starts_with(&self.root) {
            let _ = fs::remove_dir_all(path);
            let _ = fs::remove_file(path);
        }
    }

    /// Remove every batch directory, including orphans.
    pub fn clear_batches(&self) -> io::Result<()> {
        reset_dir(&self.root.join(BATCH_DIR))
    }

    /// Remove every temporary request payload.
    pub fn clear_tmp(&self) -> io::Result<()> {
        reset_dir(&self.root.join(TMP_DIR))
    }
}

/// A guard that removes a temporary request payload on drop.
#[derive(Debug)]
pub struct TempPayload {
    path: PathBuf,
}

impl TempPayload {
    /// Take ownership of one temporary path.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// The temporary path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempPayload {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn reset_dir(path: &Path) -> io::Result<()> {
    if path.exists() {
        fs::remove_dir_all(path)?;
    }
    fs::create_dir_all(path)
}

fn codec() -> impl bincode::config::Config {
    bincode::config::standard().with_limit::<{ 32 * 1024 * 1024 }>()
}

fn encode_begin(record: &BeginRecord) -> Result<Vec<u8>, Fault> {
    bincode::serde::encode_to_vec(record, codec())
        .map_err(|error| Fault::detail(ErrorCode::Internal, format!("begin encode: {error}")))
}

fn decode_begin(bytes: &[u8]) -> Result<BeginRecord, Fault> {
    let (record, used): (BeginRecord, usize) = bincode::serde::decode_from_slice(bytes, codec())
        .map_err(|error| Fault::detail(ErrorCode::Internal, format!("begin decode: {error}")))?;
    if used != bytes.len() {
        return Err(Fault::detail(
            ErrorCode::Internal,
            "begin record has trailing bytes",
        ));
    }
    Ok(record)
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::mmap::types::{EntryKind, EntryOp, ROOT_MODE};
    use tempfile::TempDir;

    fn record() -> BeginRecord {
        BeginRecord {
            entries: vec![ManifestEntry {
                name: "a".to_owned(),
                ino: [7; 16],
                kind: EntryKind::File,
                op: EntryOp::Put,
                from_name: None,
                mode: 0o644,
                uid: 1,
                gid: 2,
                mtime_ns: 3,
                size: 4,
                file_root: [8; 32],
                content_hash: Some([9; 32]),
                target: None,
            }],
            dir_attrs: DirAttrs {
                mode: ROOT_MODE,
                uid: 0,
                gid: 0,
                mtime_ns: 0,
            },
            mode: UploadMode::Delta.as_u32() as u8,
        }
    }

    #[test]
    fn begin_record_round_trips() {
        let temp = TempDir::new().unwrap();
        let spool = Spool::open(temp.path()).unwrap();
        let batch = BatchId::new_random();
        spool.create_batch(batch).unwrap();
        spool.write_begin(batch, &record()).unwrap();
        let got = spool.read_begin(batch).unwrap();
        assert_eq!(got.entries, record().entries);
        assert_eq!(got.dir_attrs, record().dir_attrs);
        assert_eq!(got.mode().unwrap(), UploadMode::Delta);
        spool.remove_batch(batch);
        assert!(!spool.batch_dir(batch).exists());
    }

    #[test]
    fn temporary_payload_is_removed_on_drop() {
        let temp = TempDir::new().unwrap();
        let spool = Spool::open(temp.path()).unwrap();
        let path = spool.tmp_path();
        fs::write(&path, b"x").unwrap();
        {
            let _guard = TempPayload::new(path.clone());
            assert!(path.exists());
        }
        assert!(!path.exists());
    }
}
