//! Directory checkin against the clean checkout baseline.
//!
//! A checkin is a no-op when every direct entry that is locally dirty still
//! matches the clean snapshot kept in `mm_base`. The check is metadata-first:
//! only a regular file whose size, mode, owner and mtime still match the
//! baseline is hashed, so clean file bodies are never read. A hash computed
//! here is kept for the upload that follows a real difference, so one checkin
//! hashes a dirty file at most once.
//!
//! Concurrency is bounded by the directory generation. A write that lands
//! after the check takes a version lock, updates the file, and bumps the
//! directory generation in the same transaction. The publishing transaction
//! then declines to clear anything, and the caller uploads normally.

use std::collections::{HashMap, HashSet};

use crate::mmap::types::{EntryKind, FileRecord, Ino, ManifestEntry};

use super::content::{self, ContentHashes};
use super::db::{NoopBaseline, NoopClear};
use super::{Shadow, ShadowDir, ShadowError, ShadowVersion, VersionState};

/// The result of comparing one directory with its checkout baseline.
#[derive(Debug, Default)]
pub(super) struct NoopCheck {
    /// Versions to reset to their baseline values.
    pub clears: Vec<NoopClear>,
    /// Hashes already computed for a dirty file, keyed by
    /// `(ino, version, dirty generation)`.
    pub hashes: HashMap<(Ino, u64, u64), ContentHashes>,
    /// At least one dirty item differs from the baseline.
    pub differs: bool,
    /// Number of dirty items the check examined.
    pub dirty: usize,
}

impl NoopCheck {
    /// True when no dirty item differs from the baseline.
    pub fn suppressed(&self) -> bool {
        !self.differs
    }
}

#[cfg(all(test, feature = "mmap-tests"))]
thread_local! {
    /// Regular files hashed by no-op checks on this thread. Test-only.
    pub(super) static HASHED_FILES: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}

#[cfg(all(test, feature = "mmap-tests"))]
fn note_hashed_file() {
    HASHED_FILES.with(|count| count.set(count.get() + 1));
}

#[cfg(not(all(test, feature = "mmap-tests")))]
fn note_hashed_file() {}

/// What hashing one dirty file produced.
enum FileHash {
    Hashed(ContentHashes),
    Changed,
    Missing,
}

impl Shadow {
    /// Compare one directory against its clean checkout baseline.
    ///
    /// Only metadata and dirty regular-file bodies are read. Direct entries
    /// that are not dirty are compared on metadata alone; their bodies never
    /// reach the hash.
    pub(super) fn check_noop(&self, dir: &ShadowDir) -> Result<NoopCheck, ShadowError> {
        let mut check = NoopCheck::default();
        if dir.local_only || dir.batch_id.is_some() {
            // A local-only directory has no parent baseline yet, and an open
            // batch must be reconciled before any suppression is safe.
            check.differs = true;
            return Ok(check);
        }

        let base_entries = self.db.base_manifest(dir.record.ino)?;
        let local = self.db.files_with_deleted(dir.record.ino)?;
        let versions: HashMap<(Ino, u64), ShadowVersion> = self
            .db
            .versions_for_dir(dir.record.ino)?
            .into_iter()
            .map(|version| ((version.ino, version.version), version))
            .collect();

        let mut base_by_ino: HashMap<Ino, &ManifestEntry> =
            HashMap::with_capacity(base_entries.len());
        for entry in &base_entries {
            if base_by_ino.insert(entry.ino, entry).is_some() {
                check.differs = true;
                return Ok(check);
            }
        }

        let mut local_inos = HashSet::with_capacity(local.len());
        for row in &local {
            local_inos.insert(row.ino);
            let Some(baseline) = base_by_ino.get(&row.ino).copied() else {
                if row.deleted {
                    // A locally created entry that was removed again is not a
                    // change; drop the dirty marker of its tombstone version.
                    if let Some(version) = versions.get(&(row.ino, row.version)) {
                        if version.dirty_gen > 0 {
                            check.dirty += 1;
                            check.clears.push(NoopClear {
                                ino: row.ino,
                                version: row.version,
                                dirty_gen: version.dirty_gen,
                                baseline: None,
                            });
                        }
                    }
                } else {
                    check.dirty += 1;
                    check.differs = true;
                }
                continue;
            };
            if row.deleted {
                check.dirty += 1;
                check.differs = true;
                continue;
            }
            self.check_entry(&mut check, row, baseline, &versions)?;
        }

        // A baseline entry with no local row at all was removed through
        // `rmdir`, which deletes the row instead of leaving a tombstone.
        for entry in &base_entries {
            if !local_inos.contains(&entry.ino) {
                check.differs = true;
            }
        }
        Ok(check)
    }

    fn check_entry(
        &self,
        check: &mut NoopCheck,
        row: &FileRecord,
        baseline: &ManifestEntry,
        versions: &HashMap<(Ino, u64), ShadowVersion>,
    ) -> Result<(), ShadowError> {
        if row.kind != baseline.kind || row.name != baseline.name {
            check.dirty += 1;
            check.differs = true;
            return Ok(());
        }
        match row.kind {
            EntryKind::Dir => {
                let Some(child) = self.db.shadow_dir(row.ino)? else {
                    check.dirty += 1;
                    check.differs = true;
                    return Ok(());
                };
                if child.local_only || !child.clean() {
                    check.dirty += 1;
                }
                if child.local_only || attrs_differ(row, baseline) {
                    check.differs = true;
                }
            }
            EntryKind::Symlink => {
                let Some(version) = versions.get(&(row.ino, row.version)) else {
                    check.dirty += 1;
                    check.differs = true;
                    return Ok(());
                };
                let dirty = version_dirty(version);
                if dirty {
                    check.dirty += 1;
                }
                if row.size != baseline.size
                    || row.target != baseline.target
                    || attrs_differ(row, baseline)
                {
                    check.differs = true;
                    return Ok(());
                }
                if dirty {
                    let target = row.target.as_deref().unwrap_or_default();
                    let hash = *blake3::hash(target).as_bytes();
                    check.clears.push(NoopClear {
                        ino: row.ino,
                        version: row.version,
                        dirty_gen: version.dirty_gen,
                        baseline: Some(NoopBaseline {
                            size: row.size,
                            file_root: crate::mmap::base::symlink_root(target),
                            hash,
                            file_hash: None,
                            mtime_ns: baseline.mtime_ns,
                            mode: baseline.mode,
                            uid: baseline.uid,
                            gid: baseline.gid,
                        }),
                    });
                }
            }
            EntryKind::File => {
                let Some(version) = versions.get(&(row.ino, row.version)) else {
                    check.dirty += 1;
                    check.differs = true;
                    return Ok(());
                };
                let dirty = version_dirty(version);
                if dirty {
                    check.dirty += 1;
                }
                if row.size != baseline.size || attrs_differ(row, baseline) {
                    check.differs = true;
                    return Ok(());
                }
                if !dirty {
                    return Ok(());
                }
                let Some(baseline_hash) = baseline.content_hash else {
                    // A pre-upgrade baseline has no whole-file hash. Upload
                    // conservatively instead of guessing.
                    check.differs = true;
                    return Ok(());
                };
                match self.hash_dirty_file(row, version)? {
                    FileHash::Changed => check.differs = true,
                    FileHash::Missing => check.differs = true,
                    FileHash::Hashed(hashes) => {
                        let same =
                            hashes.size == baseline.size && hashes.content_hash == baseline_hash;
                        if same {
                            check.clears.push(NoopClear {
                                ino: row.ino,
                                version: row.version,
                                dirty_gen: version.dirty_gen,
                                baseline: Some(NoopBaseline {
                                    size: baseline.size,
                                    file_root: baseline.file_root,
                                    hash: baseline_hash,
                                    file_hash: Some(baseline_hash),
                                    mtime_ns: baseline.mtime_ns,
                                    mode: baseline.mode,
                                    uid: baseline.uid,
                                    gid: baseline.gid,
                                }),
                            });
                        } else {
                            check.differs = true;
                        }
                        check
                            .hashes
                            .insert((row.ino, row.version, version.dirty_gen), hashes);
                    }
                }
            }
        }
        Ok(())
    }

    /// Hash one dirty regular file while holding its version lock.
    fn hash_dirty_file(
        &self,
        row: &FileRecord,
        observed: &ShadowVersion,
    ) -> Result<FileHash, ShadowError> {
        let lock = self.version_lock(row.ino, row.version);
        let _guard = super::lock(&lock);
        let Some(current) = self.db.shadow_version(row.ino, row.version)? else {
            return Ok(FileHash::Missing);
        };
        if current.dirty_gen != observed.dirty_gen || current.state != observed.state {
            return Ok(FileHash::Changed);
        }
        let path = self.layout.object_path(&row.ino, row.version);
        if !path.exists() {
            return Ok(FileHash::Missing);
        }
        note_hashed_file();
        Ok(FileHash::Hashed(content::hash_file(&path)?))
    }
}

fn version_dirty(version: &ShadowVersion) -> bool {
    version.dirty_gen > 0 || matches!(version.state, VersionState::Dirty | VersionState::Uploading)
}

fn attrs_differ(row: &FileRecord, baseline: &ManifestEntry) -> bool {
    row.attrs.mode != baseline.mode
        || row.attrs.uid != baseline.uid
        || row.attrs.gid != baseline.gid
        || row.attrs.mtime_ns != baseline.mtime_ns
}
