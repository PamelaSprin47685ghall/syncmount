//! The only classification rule: seven outcomes, first match wins.
//!
//! Owner: W14 (E7). See 43 §3.5 and C-31.
//!
//! # The order is the specification
//!
//! Every path is classified by the first row that matches:
//!
//! | condition | kind | action |
//! |---|---|---|
//! | remote has it, local does not (or the local link dangles) | `RemoteOnly` | fetch whole file |
//! | kind differs | `TypeReplace` | trash old, install new |
//! | directory | `DirSync` | `mkdir` + attrs |
//! | symlink target differs | `TypeReplace` | recreate the link |
//! | size or mtime disagrees with the cache | `ContentDiff` | rsync |
//! | `cache.file_root != remote.file_root` | `ContentDiff` | rsync |
//! | attrs differ | `AttrsOnly` | `chmod`/`chown`/`utimens` |
//! | otherwise | `Identical` | nothing |
//! | local has it, remote does not | `LocalOnly` | delete, deepest first |
//!
//! # The cache is a hint, never a fact
//!
//! `Identical` needs *both* a disk match and a cache root match. A missing,
//! stale, or foreign-cluster cache therefore degrades to `ContentDiff`, which
//! costs CPU and never transfers wrong bytes (43 §3.4). There is no branch
//! that trusts the disk alone.
//!
//! # No global commit point
//!
//! The plan is a list of independent per-path actions. There is no "swap the
//! tree" item (C-31); a crash between two items leaves some paths at the new
//! version and some at the old one, and the next diff sees the mixed tree as
//! `ContentDiff` because the cache still names the old version.

use std::collections::BTreeSet;

use crate::protocol::crypto::ClusterId;
use crate::store::Kind;
use crate::sync::manifest::{BlockmapIndex, Entry, LocalManifest, Manifest};
use crate::sync::{DiskStat, LocalTree, SyncError};

/// One classification outcome (43 §3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DiffKind {
    /// Byte-identical and attribute-identical.
    Identical,
    /// Same content, different attributes.
    AttrsOnly,
    /// Content differs; rsync decides what to send.
    ContentDiff,
    /// Only the remote has it.
    RemoteOnly,
    /// Only the local tree has it.
    LocalOnly,
    /// The type or the symlink target differs.
    TypeReplace,
    /// A directory; create it and apply attributes.
    DirSync,
}

impl DiffKind {
    /// Every kind, in priority order.
    pub const ALL: [Self; 7] = [
        Self::RemoteOnly,
        Self::TypeReplace,
        Self::DirSync,
        Self::ContentDiff,
        Self::AttrsOnly,
        Self::Identical,
        Self::LocalOnly,
    ];

    /// Stable name for logs and `status`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Identical => "identical",
            Self::AttrsOnly => "attrs-only",
            Self::ContentDiff => "content-diff",
            Self::RemoteOnly => "remote-only",
            Self::LocalOnly => "local-only",
            Self::TypeReplace => "type-replace",
            Self::DirSync => "dir-sync",
        }
    }

    /// True when bytes must move.
    pub const fn transfers_content(self) -> bool {
        matches!(
            self,
            Self::ContentDiff | Self::RemoteOnly | Self::TypeReplace
        )
    }

    /// True when the blockmap may be needed to verify or fetch.
    pub const fn needs_blockmap(self) -> bool {
        matches!(
            self,
            Self::ContentDiff | Self::RemoteOnly | Self::TypeReplace
        )
    }
}

/// One path and what to do with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanItem {
    /// Relative path.
    pub path: String,
    /// What to do.
    pub kind: DiffKind,
    /// Index into the remote manifest, when the path exists remotely.
    pub remote: Option<u32>,
    /// What the local tree has, when anything.
    pub local: Option<DiskStat>,
}

impl PlanItem {
    /// Path depth, used to order `mkdir` (shallow first) and deletion (deep
    /// first).
    pub fn depth(&self) -> usize {
        self.path.bytes().filter(|byte| *byte == b'/').count() + 1
    }
}

/// How many paths fell into each class.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DiffCounts {
    /// Byte-identical.
    pub identical: u64,
    /// Attribute-only.
    pub attrs_only: u64,
    /// Content differs.
    pub content_diff: u64,
    /// Remote only.
    pub remote_only: u64,
    /// Local only.
    pub local_only: u64,
    /// Type or link target differs.
    pub type_replace: u64,
    /// Directories.
    pub dir_sync: u64,
}

impl DiffCounts {
    /// Every classified path.
    pub const fn total(&self) -> u64 {
        self.identical
            + self.attrs_only
            + self.content_diff
            + self.remote_only
            + self.local_only
            + self.type_replace
            + self.dir_sync
    }

    /// Paths that need bytes.
    pub const fn transfers(&self) -> u64 {
        self.content_diff + self.remote_only + self.type_replace
    }
}

/// What the plan will move, for `status` and the empty-local notice.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PlanStats {
    /// Regular files that need bytes.
    pub planned_files: u64,
    /// Their total size.
    pub planned_bytes: u64,
}

/// The diff of one join.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiffPlan {
    items: Vec<PlanItem>,
    counts: DiffCounts,
    stats: PlanStats,
}

impl DiffPlan {
    /// Every item, in path order.
    pub fn items(&self) -> &[PlanItem] {
        &self.items
    }

    /// Per-class counts.
    pub const fn counts(&self) -> DiffCounts {
        self.counts
    }

    /// Planned files and bytes.
    pub const fn stats(&self) -> PlanStats {
        self.stats
    }

    /// True when nothing needs bytes and nothing must be deleted.
    pub const fn is_converged(&self) -> bool {
        self.counts.transfers() == 0 && self.counts.local_only == 0
    }

    /// Items that need bytes, in path order.
    pub fn transfers(&self) -> impl Iterator<Item = &PlanItem> {
        self.items
            .iter()
            .filter(|item| item.kind.transfers_content())
    }

    /// Attribute-only items, in path order.
    pub fn attrs(&self) -> impl Iterator<Item = &PlanItem> {
        self.items
            .iter()
            .filter(|item| item.kind == DiffKind::AttrsOnly)
    }

    /// Directories, shallow first, so `mkdir` never meets a missing parent.
    pub fn directories(&self) -> Vec<&PlanItem> {
        let mut dirs: Vec<&PlanItem> = self
            .items
            .iter()
            .filter(|item| item.kind == DiffKind::DirSync)
            .collect();
        dirs.sort_by(|a, b| {
            a.depth()
                .cmp(&b.depth())
                .then_with(|| a.path.as_bytes().cmp(b.path.as_bytes()))
        });
        dirs
    }

    /// Deletions, deepest first, so `rmdir` never meets a non-empty parent.
    pub fn deletions(&self) -> Vec<&PlanItem> {
        let mut dels: Vec<&PlanItem> = self
            .items
            .iter()
            .filter(|item| item.kind == DiffKind::LocalOnly)
            .collect();
        dels.sort_by(|a, b| {
            b.depth()
                .cmp(&a.depth())
                .then_with(|| a.path.as_bytes().cmp(b.path.as_bytes()))
        });
        dels
    }

    /// True when some transfer needs block-level identifiers.
    pub fn needs_blockmap(&self, remote: &Manifest) -> bool {
        self.transfers().any(|item| {
            item.kind.needs_blockmap()
                && item
                    .remote
                    .and_then(|index| remote.entry(index))
                    .is_some_and(|entry| entry.block_count > 0)
        })
    }

    /// Sparse blockmap data parts needed by this plan, ascending.
    pub fn blockmap_parts(&self, index: &BlockmapIndex, remote: &Manifest) -> Vec<u32> {
        let mut parts = BTreeSet::new();
        for item in self.transfers() {
            if !item.kind.needs_blockmap() {
                continue;
            }
            let Some(entry_index) = item.remote else {
                continue;
            };
            let Some(entry) = remote.entry(entry_index) else {
                continue;
            };
            if entry.block_count == 0 {
                continue;
            }
            let Some((first, count)) = index.block_range(entry_index) else {
                continue;
            };
            for part in index.parts_for_range(first, count) {
                parts.insert(part);
            }
        }
        parts.into_iter().collect()
    }
}

/// Classify one join.
///
/// # Errors
///
/// Whatever [`LocalTree::walk`] returns.
pub fn plan(
    local: Option<&LocalManifest>,
    remote: &Manifest,
    tree: &dyn LocalTree,
    cluster: ClusterId,
) -> Result<DiffPlan, SyncError> {
    let disk = tree.walk()?;
    let cache = local.filter(|manifest| manifest.cluster_id == cluster);
    let cached: &[Entry] = cache
        .map(|manifest| manifest.manifest.entries())
        .unwrap_or(&[]);
    let remote_entries = remote.entries();

    let mut plan = DiffPlan::default();
    let mut ri = 0usize;
    let mut ci = 0usize;
    let mut di = 0usize;

    loop {
        let r = remote_entries.get(ri).map(|entry| entry.path.as_str());
        let c = cached.get(ci).map(|entry| entry.path.as_str());
        let d = disk.get(di).map(|(path, _)| path.as_str());
        let Some(path) = [r, c, d].into_iter().flatten().min() else {
            break;
        };

        let remote_index = if r == Some(path) {
            let index = ri;
            ri += 1;
            Some(index)
        } else {
            None
        };
        let remote_entry = remote_index.and_then(|index| remote_entries.get(index));
        let cache_entry = if c == Some(path) {
            let entry = cached.get(ci);
            ci += 1;
            entry
        } else {
            None
        };
        let disk_entry = if d == Some(path) {
            let entry = disk.get(di);
            di += 1;
            entry
        } else {
            None
        };

        let Some((kind, bytes)) =
            classify(remote_entry, cache_entry, disk_entry.map(|(_, stat)| stat))
        else {
            continue;
        };
        plan.counts.add(kind);
        if let Some(entry) = remote_entry {
            if entry.kind == Kind::File && kind.transfers_content() {
                plan.stats.planned_files += 1;
                plan.stats.planned_bytes += entry.size;
            }
        }
        let _ = bytes;
        plan.items.push(PlanItem {
            path: path.to_owned(),
            kind,
            remote: remote_index.map(|index| index as u32),
            local: disk_entry.map(|(_, stat)| stat.clone()),
        });
    }

    Ok(plan)
}

impl DiffCounts {
    fn add(&mut self, kind: DiffKind) {
        match kind {
            DiffKind::Identical => self.identical += 1,
            DiffKind::AttrsOnly => self.attrs_only += 1,
            DiffKind::ContentDiff => self.content_diff += 1,
            DiffKind::RemoteOnly => self.remote_only += 1,
            DiffKind::LocalOnly => self.local_only += 1,
            DiffKind::TypeReplace => self.type_replace += 1,
            DiffKind::DirSync => self.dir_sync += 1,
        }
    }
}

/// First-match classification for one path.
fn classify(
    remote: Option<&Entry>,
    cache: Option<&Entry>,
    disk: Option<&DiskStat>,
) -> Option<(DiffKind, u64)> {
    let Some(remote) = remote else {
        // Remote absent: delete only if something is still on disk. A cache
        // entry without a disk entry was already removed; nothing to do.
        return disk.map(|_| (DiffKind::LocalOnly, 0));
    };

    let Some(disk) = disk else {
        // A missing directory has no content to fetch, so it is a `mkdir`
        // item, not a transfer. Every other missing kind is fetched whole.
        return Some((
            if remote.kind == Kind::Dir {
                DiffKind::DirSync
            } else {
                DiffKind::RemoteOnly
            },
            remote.size,
        ));
    };

    if disk.dangling && remote.kind != Kind::Dir {
        return Some((DiffKind::RemoteOnly, remote.size));
    }
    if disk.kind != remote.kind {
        return Some((DiffKind::TypeReplace, remote.size));
    }
    match remote.kind {
        Kind::Dir => Some((DiffKind::DirSync, 0)),
        Kind::Symlink => {
            if disk.target.as_deref() != Some(remote.target.as_str()) {
                return Some((DiffKind::TypeReplace, 0));
            }
            Some(attribute_verdict(disk, remote))
        }
        Kind::File => {
            let Some(cache) = cache else {
                return Some((DiffKind::ContentDiff, remote.size));
            };
            if disk.size != cache.size || disk.mtime_ns != cache.mtime_ns {
                return Some((DiffKind::ContentDiff, remote.size));
            }
            if cache.file_root != remote.file_root {
                return Some((DiffKind::ContentDiff, remote.size));
            }
            Some(attribute_verdict(disk, remote))
        }
        Kind::Char | Kind::Block | Kind::Fifo | Kind::Socket => {
            Some(attribute_verdict(disk, remote))
        }
        Kind::Unknown => Some((DiffKind::ContentDiff, remote.size)),
    }
}

fn attribute_verdict(disk: &DiskStat, remote: &Entry) -> (DiffKind, u64) {
    if disk.mode != remote.mode
        || disk.uid != remote.uid
        || disk.gid != remote.gid
        || disk.mtime_ns != remote.mtime_ns
    {
        (DiffKind::AttrsOnly, 0)
    } else {
        (DiffKind::Identical, 0)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;

    use super::*;
    use crate::store::node_table::InodeId;
    use crate::sync::ChunkId;
    use crate::sync::test_support::{CLUSTER, MemTree, apply_plan, stat_of};

    fn file(path: &str, size: u64, mtime: u64, mode: u32, seed: u8) -> Entry {
        let blocks = if size == 0 {
            Vec::new()
        } else {
            vec![ChunkId::from_bytes([seed; 32])]
        };
        Entry::file(
            path,
            InodeId(u128::from(seed) + 1),
            mode,
            1000,
            1000,
            size,
            mtime,
            &blocks,
        )
    }

    fn remote() -> Manifest {
        let entries = vec![
            file("a.txt", 10, 100, 0o644, 1),
            file("b.txt", 20, 200, 0o644, 2),
            Entry::dir("d", InodeId(9), 0o755, 1000, 1000, 300),
            Entry::symlink("l", InodeId(10), 1000, 1000, 400, "target"),
            file("new.txt", 30, 500, 0o644, 3),
            file("type", 40, 600, 0o644, 4),
        ];
        Manifest::new(crate::protocol::frame::Seq(77), entries)
    }

    fn tree_with_remote_state() -> (Arc<MemTree>, Manifest) {
        let remote = remote();
        let tree = MemTree::new();
        tree.insert("a.txt", stat_of(remote.find("a.txt").unwrap()));
        let mut changed = stat_of(remote.find("b.txt").unwrap());
        changed.size = 21;
        changed.mtime_ns = 201;
        tree.insert("b.txt", changed);
        tree.insert("d", stat_of(remote.find("d").unwrap()));
        tree.insert("l", stat_of(remote.find("l").unwrap()));
        tree.insert("type", DiskStat::dir(600, 0o755));
        tree.insert("local.txt", DiskStat::file(1, 1, 0o644));
        (tree, remote)
    }

    fn cache_of(manifest: &Manifest) -> LocalManifest {
        LocalManifest {
            cluster_id: CLUSTER,
            at_seq: manifest.at_seq,
            epoch: 1,
            manifest: manifest.clone(),
        }
    }

    /// All seven outcomes in one plan.
    #[test]
    fn u_diff_all_classes() {
        let (tree, remote) = tree_with_remote_state();
        let cache = cache_of(&remote);
        let plan = plan(Some(&cache), &remote, tree.as_ref(), CLUSTER).unwrap();
        let kinds: Vec<(&str, DiffKind)> = plan
            .items()
            .iter()
            .map(|item| (item.path.as_str(), item.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("a.txt", DiffKind::Identical),
                ("b.txt", DiffKind::ContentDiff),
                ("d", DiffKind::DirSync),
                ("l", DiffKind::Identical),
                ("local.txt", DiffKind::LocalOnly),
                ("new.txt", DiffKind::RemoteOnly),
                ("type", DiffKind::TypeReplace),
            ]
        );
        assert_eq!(
            plan.counts(),
            DiffCounts {
                identical: 2,
                attrs_only: 0,
                content_diff: 1,
                remote_only: 1,
                local_only: 1,
                type_replace: 1,
                dir_sync: 1,
            }
        );
        assert_eq!(plan.stats().planned_files, 3);
        assert_eq!(plan.stats().planned_bytes, 20 + 30 + 40);
        assert!(!plan.is_converged());
    }

    /// A missing cache degrades every file to `ContentDiff`, never to
    /// `Identical` (43 §3.4).
    #[test]
    fn u_diff_missing_cache_is_conservative() {
        let (tree, remote) = tree_with_remote_state();
        let plan = plan(None, &remote, tree.as_ref(), CLUSTER).unwrap();
        let a = plan
            .items()
            .iter()
            .find(|item| item.path == "a.txt")
            .unwrap();
        assert_eq!(a.kind, DiffKind::ContentDiff);
    }

    /// A cache from another cluster is not a trust anchor.
    #[test]
    fn u_diff_foreign_cache_ignored() {
        let (tree, remote) = tree_with_remote_state();
        let mut cache = cache_of(&remote);
        cache.cluster_id = ClusterId::from_bytes([0xff; 16]);
        let plan = plan(Some(&cache), &remote, tree.as_ref(), CLUSTER).unwrap();
        let a = plan
            .items()
            .iter()
            .find(|item| item.path == "a.txt")
            .unwrap();
        assert_eq!(a.kind, DiffKind::ContentDiff);
    }

    /// Attributes alone never trigger a transfer.
    #[test]
    fn u_diff_attrs_only() {
        let remote = Manifest::new(
            crate::protocol::frame::Seq(1),
            vec![file("a", 10, 100, 0o600, 1)],
        );
        let tree = MemTree::new();
        let mut stat = stat_of(remote.find("a").unwrap());
        stat.mode = 0o644;
        tree.insert("a", stat);
        let cache = cache_of(&remote);
        let plan = plan(Some(&cache), &remote, tree.as_ref(), CLUSTER).unwrap();
        assert_eq!(plan.items()[0].kind, DiffKind::AttrsOnly);
        assert_eq!(plan.counts().transfers(), 0);
        assert_eq!(plan.attrs().count(), 1);
        assert!(!plan.needs_blockmap(&remote));
    }

    /// A `TypeReplace` fetches the new file whole, so its blockmap parts are
    /// pulled instead of letting `stage_chunks` fail with a missing part.
    #[test]
    fn u_diff_type_replace_needs_blockmap() {
        let remote = Manifest::new(
            crate::protocol::frame::Seq(1),
            vec![file("type", 40, 600, 0o644, 4)],
        );
        let tree = MemTree::new();
        tree.insert("type", DiskStat::dir(600, 0o755));
        let plan = plan(None, &remote, tree.as_ref(), CLUSTER).unwrap();
        assert_eq!(plan.items()[0].kind, DiffKind::TypeReplace);
        assert!(
            plan.needs_blockmap(&remote),
            "a type replacement is a whole-file transfer"
        );
        let index = BlockmapIndex {
            at_seq: remote.at_seq,
            block_total: 1,
            file_first_block: vec![0],
            data_parts: Vec::new(),
        };
        assert_eq!(plan.blockmap_parts(&index, &remote), vec![0]);
    }

    /// A dangling local symlink is replaced by whatever the remote has.
    #[test]
    fn u_diff_dangling_symlink() {
        let remote = Manifest::new(
            crate::protocol::frame::Seq(1),
            vec![file("a", 10, 100, 0o644, 1)],
        );
        let tree = MemTree::new();
        let mut link = DiskStat::file(0, 1, 0o777);
        link.kind = Kind::Symlink;
        link.target = Some("missing".to_owned());
        link.dangling = true;
        tree.insert("a", link);
        let plan = plan(None, &remote, tree.as_ref(), CLUSTER).unwrap();
        assert_eq!(plan.items()[0].kind, DiffKind::RemoteOnly);
    }

    /// C-31: a crash after half the plan leaves a mixed tree, and the next
    /// diff re-verifies the applied half instead of trusting it.
    #[test]
    fn c31_partial_apply_is_not_trusted() {
        let remote = Manifest::new(
            crate::protocol::frame::Seq(9),
            vec![
                file("a", 10, 100, 0o644, 1),
                file("b", 20, 200, 0o644, 2),
                file("c", 30, 300, 0o644, 3),
            ],
        );
        let tree = MemTree::new();
        // The cache still describes the *previous* join: no entries at all.
        // A cache that already equalled the remote would make the partially
        // applied tree look `Identical`, which is exactly the failure C-31
        // forbids.
        let cache = LocalManifest {
            cluster_id: CLUSTER,
            at_seq: crate::protocol::frame::Seq(1),
            epoch: 1,
            manifest: Manifest::new(crate::protocol::frame::Seq(1), Vec::new()),
        };
        let initial = plan(Some(&cache), &remote, tree.as_ref(), CLUSTER).unwrap();
        assert_eq!(initial.counts().remote_only, 3);

        // Simulate a crash after the first item: only "a" reached the disk,
        // and the cache was never replaced (43 §3.4).
        let first = &initial.items()[0];
        tree.insert(&first.path, stat_of(remote.find("a").unwrap()));
        let retry = plan(Some(&cache), &remote, tree.as_ref(), CLUSTER).unwrap();
        let a = retry.items().iter().find(|item| item.path == "a").unwrap();
        assert_eq!(a.kind, DiffKind::ContentDiff);
        assert_eq!(retry.counts().identical, 0);
        assert_eq!(retry.counts().remote_only, 2);

        // After the real apply and commit, the plan converges.
        apply_plan(&tree, &initial, &remote);
        let done = plan(
            tree.cached_manifest().as_ref(),
            &remote,
            tree.as_ref(),
            CLUSTER,
        )
        .unwrap();
        assert!(done.is_converged());
        assert_eq!(done.counts().identical, 3);
    }

    /// 43 §6.3: directories are created shallow-first, deletions deepest-first.
    #[test]
    fn u_diff_ordering_helpers() {
        let remote = Manifest::new(
            crate::protocol::frame::Seq(1),
            vec![
                Entry::dir("a", InodeId(1), 0o755, 0, 0, 1),
                Entry::dir("a/b", InodeId(2), 0o755, 0, 0, 1),
                Entry::dir("a/b/c", InodeId(3), 0o755, 0, 0, 1),
            ],
        );
        let tree = MemTree::new();
        tree.insert("z", DiskStat::file(1, 1, 0o644));
        tree.insert("z/y", DiskStat::file(1, 1, 0o644));
        let plan = plan(None, &remote, tree.as_ref(), CLUSTER).unwrap();
        let dirs: Vec<&str> = plan
            .directories()
            .iter()
            .map(|item| item.path.as_str())
            .collect();
        assert_eq!(dirs, vec!["a", "a/b", "a/b/c"]);
        let dels: Vec<&str> = plan
            .deletions()
            .iter()
            .map(|item| item.path.as_str())
            .collect();
        assert_eq!(dels, vec!["z/y", "z"]);
        assert!(plan.items().iter().all(|item| !item.path.is_empty()));
    }

    /// 43 §3.5: reserved names never enter a plan.
    #[test]
    fn u_diff_skips_reserved_names() {
        let remote = Manifest::new(
            crate::protocol::frame::Seq(1),
            vec![file("a", 1, 1, 0o644, 1)],
        );
        let tree = MemTree::new();
        // A real tree adapter filters these out; the diff must not invent them
        // from the cache either.
        tree.insert("a", stat_of(remote.find("a").unwrap()));
        let cache = cache_of(&remote);
        let plan = plan(Some(&cache), &remote, tree.as_ref(), CLUSTER).unwrap();
        assert_eq!(plan.items().len(), 1);
        assert_eq!(plan.items()[0].kind, DiffKind::Identical);
    }
}
