//! `Baseline` classification and the production local-tree adapter.
//!
//! Owner: W14 (E7). See 43 §7.
//!
//! # Why this type exists at all
//!
//! An empty local tree has no diff baseline, so every remote file is
//! `RemoteOnly` and the join transfers everything. That is allowed exactly
//! once, and the specification requires it to be *visible*: `status` and one
//! INFO line must say `empty-local full sync`. [`Baseline`] produces that
//! notice and nothing else.
//!
//! # Why it cannot become a bypass
//!
//! There is no `if baseline == Empty { full_copy() }` anywhere. The join
//! always runs diff; `Empty` is the *emergent* result of an empty tree
//! (43 §7.3). The only way to transfer without diffing would be to forge a
//! non-empty baseline, which would make the diff classify the paths as
//! `ContentDiff` and still route them through rsync.
//!
//! # Judgement is local
//!
//! The scan uses the pre-mount directory descriptor, never the server's
//! report and never user input (43 I8). It is `O(directory entries)`: a
//! million files take a second or two, before `HELLO`.

use std::path::Path;
use std::sync::Arc;

use crate::protocol::crypto::ClusterId;
use crate::protocol::frame::Seq;
use crate::store::backing::RootFd;
use crate::store::{Attr, Errno, Kind};
use crate::sync::config::SyncConfig;
use crate::sync::{DiskStat, LocalManifest, LocalTree, SyncError};

/// How much of a cluster baseline the local tree already holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Baseline {
    /// No content and no usable cache: a full transfer is unavoidable.
    Empty,
    /// Some content, or a cache that no longer matches the disk.
    Partial {
        /// Content files on disk.
        files: u64,
        /// Their total size.
        bytes: u64,
    },
    /// A usable cache whose sampled attributes still match.
    Full {
        /// Sequence the cache names.
        at_seq: Seq,
    },
}

impl Baseline {
    /// The `status.sync.baseline` value (43 §7.2).
    pub const fn label(self) -> &'static str {
        match self {
            Self::Empty => "empty-local",
            Self::Partial { .. } => "partial",
            Self::Full { .. } => "full",
        }
    }

    /// True only for [`Baseline::Empty`].
    pub const fn is_empty(self) -> bool {
        matches!(self, Self::Empty)
    }

    /// Files the local tree already holds.
    pub const fn files(self) -> u64 {
        match self {
            Self::Empty | Self::Full { .. } => 0,
            Self::Partial { files, .. } => files,
        }
    }

    /// Bytes the local tree already holds.
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Empty | Self::Full { .. } => 0,
            Self::Partial { bytes, .. } => bytes,
        }
    }
}

/// Classify the local tree.
///
/// A failed scan is reported as [`Baseline::Partial`] with zero counts: the
/// one thing it must never do is claim `Empty` and thereby hide a real local
/// baseline.
pub fn classify(tree: &dyn LocalTree, cluster: ClusterId, config: &SyncConfig) -> Baseline {
    let cache = tree
        .cached_manifest()
        .filter(|manifest| manifest.cluster_id == cluster);
    let disk = match tree.walk() {
        Ok(disk) => disk,
        Err(_) => return Baseline::Partial { files: 0, bytes: 0 },
    };

    let mut files = 0u64;
    let mut bytes = 0u64;
    for (_, stat) in &disk {
        if stat.kind == Kind::File && stat.size > 0 {
            files += 1;
            bytes = bytes.saturating_add(stat.size);
        }
    }

    if files == 0 && cache.is_none() {
        return Baseline::Empty;
    }

    if let Some(cache) = cache {
        if sample_matches(tree, &cache, config.baseline_sample()) {
            return Baseline::Full {
                at_seq: cache.at_seq,
            };
        }
    }

    Baseline::Partial { files, bytes }
}

/// Compare up to `samples` cached entries against the disk.
///
/// The stride is deterministic rather than random: a flaky classification
/// would make `status` and tests disagree for no reason, and an attacker
/// cannot influence which entries are sampled because the cache is local.
fn sample_matches(tree: &dyn LocalTree, cache: &LocalManifest, samples: usize) -> bool {
    let entries = cache.manifest.entries();
    if entries.is_empty() {
        return false;
    }
    let samples = samples.min(entries.len()).max(1);
    let stride = (entries.len() / samples).max(1);
    let mut checked = 0usize;
    let mut index = 0usize;
    while index < entries.len() && checked < samples {
        let entry = &entries[index];
        let Ok(Some(stat)) = tree.stat(&entry.path) else {
            return false;
        };
        if stat.size != entry.size || stat.mtime_ns != entry.mtime_ns {
            return false;
        }
        checked += 1;
        index += stride;
    }
    checked > 0
}

/// The production [`LocalTree`] over the pre-mount directory descriptor.
#[derive(Debug)]
pub struct FsTree {
    root: Arc<RootFd>,
    cluster: ClusterId,
}

impl FsTree {
    /// Bind a root descriptor and the cluster whose cache is trusted.
    pub fn new(root: Arc<RootFd>, cluster: ClusterId) -> Self {
        Self { root, cluster }
    }

    fn disk_stat(&self, rel: &Path, attr: &Attr) -> Result<DiskStat, SyncError> {
        let kind = attr.kind();
        let mut target = None;
        let mut dangling = false;
        if kind == Kind::Symlink {
            let path = self.root.readlink_at(rel)?;
            target = Some(
                path.to_str()
                    .ok_or_else(|| SyncError::Local("non-UTF-8 symlink target".to_owned()))?
                    .to_owned(),
            );
            dangling = match self.root.stat_at(rel, true) {
                Ok(_) => false,
                Err(err) => err == Errno::ENOENT,
            };
        }
        Ok(DiskStat {
            kind,
            size: attr.size,
            mtime_ns: mtime_ns(attr),
            mode: attr.mode,
            uid: attr.uid,
            gid: attr.gid,
            target,
            dangling,
        })
    }
}

impl LocalTree for FsTree {
    fn walk(&self) -> Result<Vec<(String, DiskStat)>, SyncError> {
        let mut out = Vec::new();
        for (path, attr) in self.root.walk_at(Path::new("."))? {
            if path.as_os_str() == "." {
                continue;
            }
            let name = path
                .to_str()
                .ok_or_else(|| SyncError::Local("non-UTF-8 path in the backing tree".to_owned()))?;
            out.push((name.to_owned(), self.disk_stat(&path, &attr)?));
        }
        out.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        Ok(out)
    }

    fn stat(&self, path: &str) -> Result<Option<DiskStat>, SyncError> {
        match self.root.stat_at(Path::new(path), false) {
            Ok(attr) => Ok(Some(self.disk_stat(Path::new(path), &attr)?)),
            Err(err) if err == Errno::ENOENT => Ok(None),
            Err(err) => Err(SyncError::from(err)),
        }
    }

    fn cached_manifest(&self) -> Option<LocalManifest> {
        LocalManifest::load(&self.root, self.cluster)
    }
}

/// Nanoseconds since the Unix epoch, saturating at zero for pre-epoch times.
fn mtime_ns(attr: &Attr) -> u64 {
    if attr.mtime.sec < 0 {
        return 0;
    }
    (attr.mtime.sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(attr.mtime.nsec.clamp(0, 999_999_999) as u64)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::store::node_table::InodeId;
    use crate::sync::ChunkId;
    use crate::sync::manifest::{Entry, Manifest};
    use crate::sync::test_support::{CLUSTER, MemTree};

    fn config() -> SyncConfig {
        SyncConfig::new()
    }

    /// 43 §7.1: no content and no cache is `Empty`.
    #[test]
    fn u_baseline_empty() {
        let tree = MemTree::new();
        assert_eq!(classify(tree.as_ref(), CLUSTER, &config()), Baseline::Empty);
        assert_eq!(Baseline::Empty.label(), "empty-local");
    }

    /// Empty files, directories and symlinks are not content (43 R14).
    #[test]
    fn u_baseline_empty_despite_zero_byte_entries() {
        let tree = MemTree::new();
        tree.insert("empty.txt", DiskStat::file(0, 1, 0o644));
        tree.insert("dir", DiskStat::dir(1, 0o755));
        let mut link = DiskStat::file(0, 1, 0o777);
        link.kind = Kind::Symlink;
        link.target = Some("x".to_owned());
        tree.insert("link", link);
        assert_eq!(classify(tree.as_ref(), CLUSTER, &config()), Baseline::Empty);
    }

    /// One byte of content is `Partial`.
    #[test]
    fn u_baseline_partial_one_byte() {
        let tree = MemTree::new();
        tree.insert("one", DiskStat::file(1, 1, 0o644));
        tree.insert("two", DiskStat::file(41, 2, 0o644));
        assert_eq!(
            classify(tree.as_ref(), CLUSTER, &config()),
            Baseline::Partial {
                files: 2,
                bytes: 42
            }
        );
    }

    /// A cache whose sampled stats match is `Full`.
    #[test]
    fn u_baseline_full() {
        let tree = MemTree::new();
        let entries = vec![
            Entry::file(
                "a",
                InodeId(1),
                0o644,
                1000,
                1000,
                10,
                100,
                &[ChunkId::from_bytes([1; 32])],
            ),
            Entry::file(
                "b",
                InodeId(2),
                0o644,
                1000,
                1000,
                20,
                200,
                &[ChunkId::from_bytes([2; 32])],
            ),
        ];
        let manifest = Manifest::new(Seq(4096), entries);
        for entry in manifest.entries() {
            tree.insert(&entry.path, crate::sync::test_support::stat_of(entry));
        }
        *tree.cached.lock().unwrap() = Some(LocalManifest {
            cluster_id: CLUSTER,
            at_seq: Seq(4096),
            epoch: 1,
            manifest,
        });
        assert_eq!(
            classify(tree.as_ref(), CLUSTER, &config()),
            Baseline::Full { at_seq: Seq(4096) }
        );
    }

    /// A cache that disagrees with the disk is not `Full`.
    #[test]
    fn u_baseline_stale_cache_is_partial() {
        let tree = MemTree::new();
        let manifest = Manifest::new(
            Seq(4096),
            vec![Entry::file(
                "a",
                InodeId(1),
                0o644,
                1000,
                1000,
                10,
                100,
                &[ChunkId::from_bytes([1; 32])],
            )],
        );
        let mut stat = DiskStat::file(11, 100, 0o644);
        stat.size = 11;
        tree.insert("a", stat);
        *tree.cached.lock().unwrap() = Some(LocalManifest {
            cluster_id: CLUSTER,
            at_seq: Seq(4096),
            epoch: 1,
            manifest,
        });
        assert_eq!(
            classify(tree.as_ref(), CLUSTER, &config()),
            Baseline::Partial {
                files: 1,
                bytes: 11
            }
        );
    }

    /// A cache from another cluster is not a baseline.
    #[test]
    fn u_baseline_foreign_cache_ignored() {
        let tree = MemTree::new();
        let manifest = Manifest::new(Seq(1), Vec::new());
        *tree.cached.lock().unwrap() = Some(LocalManifest {
            cluster_id: ClusterId::from_bytes([9; 16]),
            at_seq: Seq(1),
            epoch: 1,
            manifest,
        });
        assert_eq!(classify(tree.as_ref(), CLUSTER, &config()), Baseline::Empty);
    }

    /// The production adapter reads a real directory through a root fd.
    #[test]
    fn i_baseline_fs_tree_scan() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), b"hello").unwrap();
        std::fs::create_dir(dir.path().join("d")).unwrap();
        std::os::unix::fs::symlink("a", dir.path().join("l")).unwrap();
        let root = Arc::new(RootFd::open_before_mount(dir.path()).unwrap());
        let tree = FsTree::new(root, CLUSTER);
        let walked = tree.walk().unwrap();
        let names: Vec<&str> = walked.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, vec!["a", "d", "l"]);
        assert_eq!(tree.stat("a").unwrap().unwrap().size, 5);
        assert!(tree.stat("missing").unwrap().is_none());
        assert_eq!(
            tree.stat("l").unwrap().unwrap().target.as_deref(),
            Some("a")
        );
        assert!(!tree.stat("l").unwrap().unwrap().dangling);
        assert_eq!(
            classify(&tree, CLUSTER, &config()),
            Baseline::Partial { files: 1, bytes: 5 }
        );
    }
}
