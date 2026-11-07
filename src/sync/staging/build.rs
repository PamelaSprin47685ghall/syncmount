//! Build the flat staging tree from a `(path, chunk_id, blob)` stream.
//!
//! Every target file gets exactly one staging name, `<n>.sm-tmp`, in the flat
//! `.syncmount-staging/tree/` directory. The target directory structure is
//! never recreated under staging: the plan carries the target path separately
//! (43 §6.2). Multiple chunks for the same target are appended in stream
//! order; the chunk's plaintext hash is verified before a byte is written.
//!
//! `finish` sets the final mode, `fsync`s every staged file and the tree
//! directory, and returns the mapping the apply step needs.

use std::collections::BTreeMap;
use std::fmt;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustix::fs::{Mode, OFlags};

use crate::store::backing::RootFd;
use crate::store::{Errno, STAGING_TREE};

use super::plan::ApplyPlan;
use super::{
    STAGE_SUFFIX, StagingError, TMP_DIR, TRASH_DIR, ensure_layout, remove_entry, validate_target,
};
use crate::sync::chunk::{ChunkCipher, ChunkId, ChunkKind};

/// One file ready to be renamed into place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedFile {
    /// Target path relative to the backing root.
    pub target: PathBuf,
    /// Staging path relative to the backing root.
    pub staging: PathBuf,
    /// Final permission bits.
    pub mode: u32,
    /// Plaintext bytes written.
    pub bytes: u64,
}

/// What a crash-recovery sweep removed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CleanupReport {
    /// Entries removed from `tree/`.
    pub tree: u64,
    /// Entries removed from `trash/`.
    pub trash: u64,
    /// Entries removed from `tmp/`.
    pub tmp: u64,
}

impl CleanupReport {
    /// Total entries removed.
    pub const fn total(self) -> u64 {
        self.tree + self.trash + self.tmp
    }
}

struct OpenStage {
    file: StagedFile,
    fd: Option<OwnedFd>,
}

/// A staging build in progress.
pub struct StagingBuild {
    root: Arc<RootFd>,
    next: u64,
    open: BTreeMap<PathBuf, OpenStage>,
    order: Vec<PathBuf>,
}

impl fmt::Debug for StagingBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StagingBuild")
            .field("next", &self.next)
            .field("files", &self.open.len())
            .finish_non_exhaustive()
    }
}

impl StagingBuild {
    /// Start a build below `root`, creating the staging directories.
    pub fn new(root: Arc<RootFd>) -> Result<Self, StagingError> {
        ensure_layout(&root)?;
        Ok(Self {
            root,
            next: 0,
            open: BTreeMap::new(),
            order: Vec::new(),
        })
    }

    /// Stage one chunk of `target`.
    ///
    /// The blob is decrypted and its plaintext hash checked before the bytes
    /// enter staging. Repeated calls for one target append, which is exactly
    /// the order of the `(path, chunk_id, blob)` stream.
    pub fn stage_chunk(
        &mut self,
        target: &Path,
        chunk_id: ChunkId,
        blob: &[u8],
        cipher: &ChunkCipher,
    ) -> Result<&StagedFile, StagingError> {
        validate_target(target)?;
        let plaintext = cipher.open(ChunkKind::File, &chunk_id, blob)?;
        self.append(target, &plaintext, 0o644)
    }

    /// Stage an in-memory file (tests, symlink targets, small fixtures).
    pub fn stage_bytes(
        &mut self,
        target: &Path,
        data: &[u8],
        mode: u32,
    ) -> Result<&StagedFile, StagingError> {
        validate_target(target)?;
        self.append(target, data, mode)
    }

    /// Stage one rsync segment at an explicit file offset.
    ///
    /// Segments may complete out of order; `patch_to` output for one segment
    /// can be written to a `Vec` and handed here with the segment's offset.
    /// Unlike [`Self::stage_bytes`], this does not append: it writes at
    /// `offset` and records the high-water mark.
    pub fn stage_segment(
        &mut self,
        target: &Path,
        offset: u64,
        data: &[u8],
        mode: u32,
    ) -> Result<&StagedFile, StagingError> {
        validate_target(target)?;
        if !self.open.contains_key(target) {
            self.create(target, mode)?;
        }
        let stage = self
            .open
            .get_mut(target)
            .ok_or_else(|| StagingError::AlreadyInstalled(target.display().to_string()))?;
        let fd = stage
            .fd
            .as_ref()
            .ok_or_else(|| StagingError::AlreadyInstalled(target.display().to_string()))?;
        write_all_at(fd, data, offset)?;
        stage.file.bytes = stage
            .file
            .bytes
            .max(offset.saturating_add(data.len() as u64));
        Ok(&stage.file)
    }

    /// Consume a whole `(path, chunk_id, blob)` stream.
    pub fn stage_stream<I>(&mut self, cipher: &ChunkCipher, items: I) -> Result<(), StagingError>
    where
        I: IntoIterator<Item = (PathBuf, ChunkId, Vec<u8>)>,
    {
        for (target, chunk_id, blob) in items {
            self.stage_chunk(&target, chunk_id, &blob, cipher)?;
        }
        Ok(())
    }

    /// Finish writing: set modes, `fsync` files and the tree directory.
    ///
    /// Returns the staged files in first-appearance order.
    pub fn finish(mut self) -> Result<Vec<StagedFile>, StagingError> {
        for stage in self.open.values_mut() {
            if let Some(fd) = stage.fd.take() {
                rustix::fs::fchmod(&fd, Mode::from_raw_mode(stage.file.mode))
                    .map_err(Errno::from)?;
                rustix::fs::fsync(&fd).map_err(Errno::from)?;
            }
        }
        self.root
            .fsync_at(Path::new(STAGING_TREE), false)
            .map_err(StagingError::from)?;
        Ok(self
            .order
            .iter()
            .filter_map(|target| self.open.get(target).map(|stage| stage.file.clone()))
            .collect())
    }

    /// Finish and turn the result into install items.
    ///
    /// Directory items are not synthesized here: their modes and attributes
    /// come from the diff plan. The caller pushes them before these installs.
    pub fn into_plan(self) -> Result<ApplyPlan, StagingError> {
        let files = self.finish()?;
        let mut plan = ApplyPlan::new();
        for file in files {
            plan.push_install(file.staging, file.target)?;
        }
        Ok(plan)
    }

    fn append(
        &mut self,
        target: &Path,
        data: &[u8],
        mode: u32,
    ) -> Result<&StagedFile, StagingError> {
        if !self.open.contains_key(target) {
            self.create(target, mode)?;
        }
        let stage = self
            .open
            .get_mut(target)
            .ok_or_else(|| StagingError::AlreadyInstalled(target.display().to_string()))?;
        let fd = stage
            .fd
            .as_ref()
            .ok_or_else(|| StagingError::AlreadyInstalled(target.display().to_string()))?;
        write_all(fd, data)?;
        stage.file.bytes = stage.file.bytes.saturating_add(data.len() as u64);
        Ok(&stage.file)
    }

    fn create(&mut self, target: &Path, mode: u32) -> Result<(), StagingError> {
        let staging = Path::new(STAGING_TREE).join(format!("{}{STAGE_SUFFIX}", self.next));
        self.next = self.next.wrapping_add(1);
        let fd = self.root.open_at(
            &staging,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(0o600),
        )?;
        self.open.insert(
            target.to_path_buf(),
            OpenStage {
                file: StagedFile {
                    target: target.to_path_buf(),
                    staging,
                    mode,
                    bytes: 0,
                },
                fd: Some(fd),
            },
        );
        self.order.push(target.to_path_buf());
        Ok(())
    }
}

/// Remove every leftover from `tree/`, `trash/` and `tmp/`.
///
/// Chunks are untouched: the cache survives a crash and makes the next JOIN
/// cheaper (43 §6.4). Called during BOOT, before mounting.
pub fn cleanup_stale(root: &RootFd) -> Result<CleanupReport, StagingError> {
    Ok(CleanupReport {
        tree: cleanup_dir(root, Path::new(STAGING_TREE))?,
        trash: cleanup_dir(root, Path::new(TRASH_DIR))?,
        tmp: cleanup_dir(root, Path::new(TMP_DIR))?,
    })
}

fn cleanup_dir(root: &RootFd, dir: &Path) -> Result<u64, StagingError> {
    let entries = match root.list_at(dir) {
        Ok(entries) => entries,
        Err(err) if err == Errno::ENOENT => return Ok(0),
        Err(err) => return Err(err.into()),
    };
    let mut removed = 0u64;
    for entry in entries {
        removed = removed.saturating_add(remove_entry(root, &dir.join(entry.name))?);
    }
    Ok(removed)
}

fn write_all(fd: &OwnedFd, mut data: &[u8]) -> Result<(), StagingError> {
    while !data.is_empty() {
        let written = rustix::io::write(fd, data).map_err(Errno::from)?;
        if written == 0 {
            return Err(Errno::EIO.into());
        }
        data = &data[written..];
    }
    Ok(())
}

fn write_all_at(fd: &OwnedFd, data: &[u8], offset: u64) -> Result<(), StagingError> {
    let mut written = 0usize;
    while written < data.len() {
        let count = rustix::io::pwrite(fd, &data[written..], offset + written as u64)
            .map_err(Errno::from)?;
        if count == 0 {
            return Err(Errno::EIO.into());
        }
        written += count;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::store::chunk_store::{ChunkStore, PutOutcome};
    use crate::store::{RootFd, STAGING_DIR};
    use crate::sync::staging::apply::apply;
    use tempfile::TempDir;

    const KEY: [u8; 32] = [0x21; 32];

    fn setup(tag: &str) -> (TempDir, Arc<RootFd>) {
        let tmp = TempDir::new().unwrap_or_else(|err| panic!("tempdir {tag}: {err}"));
        let mount = tmp.path().join("mnt");
        std::fs::create_dir(&mount).unwrap_or_else(|err| panic!("mkdir {tag}: {err}"));
        let root =
            RootFd::open_before_mount(&mount).unwrap_or_else(|err| panic!("root {tag}: {err}"));
        (tmp, Arc::new(root))
    }

    fn read(root: &RootFd, rel: &Path) -> Vec<u8> {
        let fd = root
            .open_at(rel, OFlags::RDONLY, Mode::empty())
            .unwrap_or_else(|err| panic!("open {}: {err}", rel.display()));
        let attr = root.stat_at(rel, false).unwrap();
        let mut out = vec![0u8; attr.size as usize];
        let mut off = 0usize;
        while off < out.len() {
            let count = rustix::io::pread(&fd, &mut out[off..], off as u64).unwrap();
            if count == 0 {
                break;
            }
            off += count;
        }
        out
    }

    /// 45:I-JOIN / 31:M3-7
    #[test]
    fn u_staging_build_flat_layout() {
        let (_tmp, root) = setup("flat");
        let cipher = ChunkCipher::new(KEY);
        let mut build = StagingBuild::new(root.clone()).unwrap();

        let one = cipher.seal(ChunkKind::File, b"one").unwrap();
        let two = cipher.seal(ChunkKind::File, b"two").unwrap();
        build
            .stage_chunk(Path::new("a/b/c"), one.chunk_id, &one.blob, &cipher)
            .unwrap();
        build
            .stage_chunk(Path::new("d"), two.chunk_id, &two.blob, &cipher)
            .unwrap();
        let files = build.finish().unwrap();

        assert_eq!(files.len(), 2);
        assert_eq!(
            files[0].staging,
            Path::new(".syncmount-staging/tree/0.sm-tmp")
        );
        assert_eq!(
            files[1].staging,
            Path::new(".syncmount-staging/tree/1.sm-tmp")
        );
        assert_eq!(files[0].target, Path::new("a/b/c"));
        assert_eq!(files[0].bytes, 3);

        let names: Vec<_> = root
            .list_at(Path::new(STAGING_TREE))
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert_eq!(names.len(), 2, "staging tree must stay flat");
        assert_eq!(read(&root, &files[0].staging), b"one");
        assert_eq!(read(&root, &files[1].staging), b"two");
        assert!(
            root.stat_at(Path::new(".syncmount-staging/tree/a"), false)
                .is_err(),
            "no target directory may be recreated under staging"
        );
    }

    /// 45:I-JOIN
    #[test]
    fn u_staging_stream_appends_chunks_per_path() {
        let (_tmp, root) = setup("append");
        let cipher = ChunkCipher::new(KEY);
        let first = cipher.seal(ChunkKind::File, b"hello ").unwrap();
        let second = cipher.seal(ChunkKind::File, b"world").unwrap();
        let mut build = StagingBuild::new(root.clone()).unwrap();
        build
            .stage_stream(
                &cipher,
                [
                    (PathBuf::from("f"), first.chunk_id, first.blob.clone()),
                    (PathBuf::from("f"), second.chunk_id, second.blob.clone()),
                ],
            )
            .unwrap();
        let files = build.finish().unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].bytes, 11);
        assert_eq!(read(&root, &files[0].staging), b"hello world");
    }

    /// 45:I-JOIN / 31:M3-4
    #[test]
    fn u_staging_segments_may_arrive_out_of_order() {
        let (_tmp, root) = setup("segments");
        let mut build = StagingBuild::new(root.clone()).unwrap();
        build
            .stage_segment(Path::new("f"), 6, b"world", 0o644)
            .unwrap();
        build
            .stage_segment(Path::new("f"), 0, b"hello ", 0o644)
            .unwrap();
        let files = build.finish().unwrap();

        assert_eq!(files[0].bytes, 11);
        assert_eq!(read(&root, &files[0].staging), b"hello world");
    }

    /// 45:I-JOIN / 31:M3-7
    #[test]
    fn u_staging_stream_to_apply_end_to_end() {
        let (_tmp, root) = setup("stream-apply");
        let cipher = ChunkCipher::new(KEY);
        let first = cipher.seal(ChunkKind::File, b"hello ").unwrap();
        let second = cipher.seal(ChunkKind::File, b"world").unwrap();
        let mut build = StagingBuild::new(root.clone()).unwrap();
        build
            .stage_stream(
                &cipher,
                [
                    (PathBuf::from("d/f"), first.chunk_id, first.blob),
                    (PathBuf::from("d/f"), second.chunk_id, second.blob),
                ],
            )
            .unwrap();
        let mut plan = build.into_plan().unwrap();
        plan.push_mkdir(PathBuf::from("d"), 0o755).unwrap();
        let report = apply(&root, &plan).unwrap();

        assert_eq!(report.installed, 1);
        assert_eq!(read(&root, Path::new("d/f")), b"hello world");
        assert!(root.list_at(Path::new(STAGING_TREE)).unwrap().is_empty());
    }

    /// 31:M3-7
    #[test]
    fn u_staging_rejects_reserved_names() {
        let (_tmp, root) = setup("reserved");
        let cipher = ChunkCipher::new(KEY);
        let sealed = cipher.seal(ChunkKind::File, b"x").unwrap();
        let mut build = StagingBuild::new(root).unwrap();

        for target in [
            ".syncmount-staging/x",
            ".syncmount-manifest",
            ".audit.log",
            "dir/.syncmount",
        ] {
            let err = build
                .stage_chunk(Path::new(target), sealed.chunk_id, &sealed.blob, &cipher)
                .expect_err("reserved target must fail");
            assert!(
                matches!(err, StagingError::ReservedName(_)),
                "{target}: {err:?}"
            );
        }
        assert_eq!(build.next, 0, "no staging file may be created");
    }

    /// 45:§6.3 R9
    #[test]
    fn u_staging_cleanup_preserves_chunks() {
        let (_tmp, root) = setup("cleanup");
        let mut build = StagingBuild::new(root.clone()).unwrap();
        build.stage_bytes(Path::new("f"), b"staged", 0o644).unwrap();
        let _ = build.finish().unwrap();

        std::fs::write(root.mountpoint().join(".syncmount-staging/trash/1"), b"old").unwrap();
        std::fs::write(
            root.mountpoint().join(".syncmount-staging/tmp/spill"),
            b"tmp",
        )
        .unwrap();

        let store = ChunkStore::open(root.clone()).unwrap();
        let id = ChunkId::of_plaintext(b"cached");
        let blob = vec![0x5a; 64];
        assert_eq!(
            store
                .put(
                    ChunkKind::File,
                    &id,
                    &blob,
                    crate::store::chunk_store::BlobId::of_blob(&blob),
                )
                .unwrap(),
            PutOutcome::Stored
        );

        let report = cleanup_stale(&root).unwrap();
        assert_eq!(report.tree, 1);
        assert_eq!(report.trash, 1);
        assert_eq!(report.tmp, 1);
        assert_eq!(report.total(), 3);
        assert!(root.list_at(Path::new(STAGING_TREE)).unwrap().is_empty());
        assert!(root.list_at(Path::new(TRASH_DIR)).unwrap().is_empty());
        assert!(root.list_at(Path::new(TMP_DIR)).unwrap().is_empty());

        let reopened = ChunkStore::open(root).unwrap();
        assert!(reopened.has(ChunkKind::File, &id), "chunk cache survives");
        assert_eq!(reopened.get(ChunkKind::File, &id).unwrap().unwrap(), blob);
    }

    /// 45:I-JOIN
    #[test]
    fn u_staging_rejects_tampered_chunk() {
        let (_tmp, root) = setup("tampered");
        let cipher = ChunkCipher::new(KEY);
        let sealed = cipher.seal(ChunkKind::File, b"good").unwrap();
        let mut blob = sealed.blob.clone();
        blob[0] ^= 0xff;
        let mut build = StagingBuild::new(root.clone()).unwrap();

        let err = build
            .stage_chunk(Path::new("f"), sealed.chunk_id, &blob, &cipher)
            .expect_err("tampered chunk must fail");
        assert!(matches!(err, StagingError::Chunk(_)));
        assert!(
            root.list_at(Path::new(STAGING_TREE)).unwrap().is_empty(),
            "no partial file may be staged"
        );
        assert!(root.list_at(Path::new(STAGING_DIR)).is_ok());
    }

    /// 45:§6.3 R9
    #[test]
    fn u_staging_cleanup_on_empty_layout() {
        let (_tmp, root) = setup("empty-clean");
        StagingBuild::new(root.clone()).unwrap();
        assert_eq!(cleanup_stale(&root).unwrap().total(), 0);
    }
}
