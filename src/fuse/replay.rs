//! The replay engine's view of the backing tree.
//!
//! [`ReplayView`] decorates [`PosixBacking`] with two W13b responsibilities:
//!
//! 1. **Idempotent materialisation.** The FUSE write path applies mutations
//!    locally before the operation is echoed (41 §3.1, W13b). The echo must
//!    therefore find the effect already on disk and treat it as done. The
//!    rule is narrow: a creation whose name already maps to the same
//!    [`InodeId`] is a no-op; a removal whose name is already gone is a
//!    no-op; a rename whose source is gone and destination is present is a
//!    no-op. Anything else is a genuine divergence and keeps its POSIX errno
//!    (`EEXIST`, `ENOENT`), which the replayer turns into a fatal
//!    materialisation failure rather than a silent fork.
//! 2. **Kernel invalidation.** After the disk has the new state, the cached
//!    dentries and inode attributes are dropped through [`Notify`]. The order
//!    is fixed: disk first, notification second (41 §4).
//!
//! The wrapper never decides the total order; it only absorbs effects that
//! the local tree already shows.

use std::ffi::OsStr;
use std::sync::Arc;

use fuser::INodeNo;

use crate::client::ReplayBacking;
use crate::store::node_table::InodeId;
use crate::store::{AttrDelta, BackingStore, Effect, Errno, NodeTable, PosixBacking};

use super::notify::Notify;

/// A [`ReplayBacking`] that keeps the FUSE view consistent with the disk.
#[derive(Debug)]
pub struct ReplayView {
    backing: Arc<PosixBacking>,
    nodes: Arc<NodeTable>,
    notify: Notify,
}

impl ReplayView {
    /// Wrap a shared backing store and its node table.
    pub fn new(backing: Arc<PosixBacking>, nodes: Arc<NodeTable>, notify: Notify) -> Self {
        Self {
            backing,
            nodes,
            notify,
        }
    }

    /// What the local tree currently shows at `parent/name`.
    fn entry(&self, parent: InodeId, name: &OsStr) -> Result<DiskEntry, Errno> {
        if let Some(id) = self.nodes.lookup(parent, name) {
            return Ok(DiskEntry::Known(id));
        }
        match BackingStore::lookup(self.backing.as_ref(), parent, name) {
            Ok(_) => Ok(DiskEntry::Unknown),
            Err(err) if err == Errno::ENOENT => Ok(DiskEntry::Absent),
            Err(err) => Err(err),
        }
    }

    fn invalidate_entry(&self, parent: InodeId, name: &OsStr) {
        if let Some(ino) = self.nodes.ino_of(parent) {
            let _ = self.notify.invalidate_entry(INodeNo(ino), name);
        }
    }

    fn invalidate_range(&self, id: InodeId, offset: u64, len: usize) {
        let offset = i64::try_from(offset).unwrap_or(i64::MAX);
        let len = i64::try_from(len).unwrap_or(i64::MAX);
        self.invalidate_inode(id, offset, len);
    }

    fn invalidate_inode(&self, id: InodeId, offset: i64, len: i64) {
        if let Some(ino) = self.nodes.ino_of(id) {
            let _ = self.notify.invalidate_inode(INodeNo(ino), offset, len);
        }
    }

    fn invalidate_all(&self, id: InodeId) {
        self.invalidate_inode(id, 0, -1);
    }

    fn invalidate_attr(&self, id: InodeId) {
        self.invalidate_inode(id, 0, 0);
    }
}

/// One directory entry as the local tree sees it.
enum DiskEntry {
    /// Absent from both the table and the disk.
    Absent,
    /// Present and indexed.
    Known(InodeId),
    /// Present on disk but not indexed (bootstrap or a lost lookup).
    Unknown,
}

impl ReplayBacking for ReplayView {
    fn mkdir(&self, parent: InodeId, name: &OsStr, id: InodeId, mode: u32) -> Result<(), Errno> {
        let result = match self.entry(parent, name)? {
            DiskEntry::Known(existing) if existing == id => Ok(()),
            DiskEntry::Known(_) | DiskEntry::Unknown => Err(Errno::EEXIST),
            DiskEntry::Absent => {
                ReplayBacking::mkdir(self.backing.as_ref(), parent, name, id, mode)
            }
        };
        if result.is_ok() {
            self.invalidate_entry(parent, name);
            self.invalidate_all(id);
            self.invalidate_attr(parent);
        }
        result
    }

    fn create(&self, parent: InodeId, name: &OsStr, id: InodeId, mode: u32) -> Result<(), Errno> {
        let result = match self.entry(parent, name)? {
            DiskEntry::Known(existing) if existing == id => Ok(()),
            DiskEntry::Known(_) | DiskEntry::Unknown => Err(Errno::EEXIST),
            DiskEntry::Absent => {
                ReplayBacking::create(self.backing.as_ref(), parent, name, id, mode)
            }
        };
        if result.is_ok() {
            self.invalidate_entry(parent, name);
            self.invalidate_all(id);
            self.invalidate_attr(parent);
        }
        result
    }

    fn symlink(
        &self,
        parent: InodeId,
        name: &OsStr,
        id: InodeId,
        target: &std::path::Path,
    ) -> Result<(), Errno> {
        let result = match self.entry(parent, name)? {
            DiskEntry::Known(existing) if existing == id => Ok(()),
            DiskEntry::Known(_) | DiskEntry::Unknown => Err(Errno::EEXIST),
            DiskEntry::Absent => {
                ReplayBacking::symlink(self.backing.as_ref(), parent, name, id, target)
            }
        };
        if result.is_ok() {
            self.invalidate_entry(parent, name);
            self.invalidate_all(id);
            self.invalidate_attr(parent);
        }
        result
    }

    fn unlink(&self, parent: InodeId, name: &OsStr) -> Result<(), Errno> {
        let target = self.nodes.lookup(parent, name);
        let result = match self.entry(parent, name)? {
            DiskEntry::Absent => Ok(()),
            DiskEntry::Known(_) | DiskEntry::Unknown => {
                ReplayBacking::unlink(self.backing.as_ref(), parent, name)
            }
        };
        if result.is_ok() {
            self.invalidate_entry(parent, name);
            if let Some(id) = target {
                self.invalidate_all(id);
            }
            self.invalidate_attr(parent);
        }
        result
    }

    fn rmdir(&self, parent: InodeId, name: &OsStr) -> Result<(), Errno> {
        let target = self.nodes.lookup(parent, name);
        let result = match self.entry(parent, name)? {
            DiskEntry::Absent => Ok(()),
            DiskEntry::Known(_) | DiskEntry::Unknown => {
                ReplayBacking::rmdir(self.backing.as_ref(), parent, name)
            }
        };
        if result.is_ok() {
            self.invalidate_entry(parent, name);
            if let Some(id) = target {
                self.invalidate_all(id);
            }
            self.invalidate_attr(parent);
        }
        result
    }

    fn rename(&self, from: (InodeId, &OsStr), to: (InodeId, &OsStr)) -> Result<(), Errno> {
        let source = self.entry(from.0, from.1)?;
        let destination = self.entry(to.0, to.1)?;
        let source_id = self.nodes.lookup(from.0, from.1);
        let result = match (source, destination) {
            (DiskEntry::Absent, DiskEntry::Absent) => Err(Errno::ENOENT),
            // The local write path already moved it: the source is gone and
            // the destination exists.
            (DiskEntry::Absent, DiskEntry::Known(_) | DiskEntry::Unknown) => Ok(()),
            (DiskEntry::Known(_) | DiskEntry::Unknown, _) => {
                ReplayBacking::rename(self.backing.as_ref(), from, to)
            }
        };
        if result.is_ok() {
            self.invalidate_entry(from.0, from.1);
            self.invalidate_entry(to.0, to.1);
            if let Some(id) = source_id {
                self.invalidate_attr(id);
            }
            self.invalidate_attr(from.0);
            self.invalidate_attr(to.0);
        }
        result
    }

    fn link(&self, id: InodeId, parent: InodeId, name: &OsStr) -> Result<(), Errno> {
        let result = match self.entry(parent, name)? {
            DiskEntry::Known(existing) if existing == id => Ok(()),
            DiskEntry::Known(_) | DiskEntry::Unknown => Err(Errno::EEXIST),
            DiskEntry::Absent => ReplayBacking::link(self.backing.as_ref(), id, parent, name),
        };
        if result.is_ok() {
            self.invalidate_entry(parent, name);
            self.invalidate_attr(id);
            self.invalidate_attr(parent);
        }
        result
    }

    fn write_at(&self, id: InodeId, off: u64, data: &[u8]) -> Result<(), Errno> {
        ReplayBacking::write_at(self.backing.as_ref(), id, off, data)?;
        self.invalidate_range(id, off, data.len());
        self.invalidate_attr(id);
        Ok(())
    }

    fn truncate(&self, id: InodeId, size: u64) -> Result<(), Errno> {
        ReplayBacking::truncate(self.backing.as_ref(), id, size)?;
        self.invalidate_all(id);
        Ok(())
    }

    fn set_attr(&self, id: InodeId, delta: &AttrDelta) -> Result<(), Errno> {
        ReplayBacking::set_attr(self.backing.as_ref(), id, delta)?;
        if delta.size.is_some() {
            self.invalidate_all(id);
        } else {
            self.invalidate_attr(id);
        }
        Ok(())
    }

    fn apply_effect(&self, id: InodeId, effect: &Effect) -> Result<(), Errno> {
        ReplayBacking::apply_effect(self.backing.as_ref(), id, effect)?;
        match effect {
            Effect::Write { off, data } => {
                self.invalidate_range(id, *off, data.len());
                self.invalidate_attr(id);
            }
            Effect::Truncate { .. } => self.invalidate_all(id),
            Effect::SetAttr(delta) => {
                if delta.size.is_some() {
                    self.invalidate_all(id);
                } else {
                    self.invalidate_attr(id);
                }
            }
            Effect::Xattr { .. } => self.invalidate_attr(id),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    use std::path::Path;
    use std::sync::Arc;

    use tempfile::TempDir;

    use crate::fuse::notify::Invalidation;
    use crate::store::{PosixBacking, RootFd};

    struct Fixture {
        tmp: TempDir,
        view: ReplayView,
        nodes: Arc<NodeTable>,
        notify: Notify,
    }

    fn fixture() -> Fixture {
        let tmp = TempDir::new().unwrap();
        let root = RootFd::open_before_mount(tmp.path()).unwrap();
        let nodes = Arc::new(NodeTable::new());
        let backing = Arc::new(PosixBacking::with_nodes(Arc::new(root), Arc::clone(&nodes)));
        let notify = Notify::new();
        let view = ReplayView::new(backing, Arc::clone(&nodes), notify.clone());
        Fixture {
            tmp,
            view,
            nodes,
            notify,
        }
    }

    /// W13b: the echo of a locally created directory is a no-op.
    #[test]
    fn u_fuse_replay_view_mkdir_is_idempotent() {
        let fixture = fixture();
        let id = InodeId(7);
        fixture
            .view
            .mkdir(InodeId::ROOT, OsStr::new("d"), id, 0o755)
            .unwrap();
        assert!(fixture.tmp.path().join("d").is_dir());
        assert_eq!(
            fixture.nodes.lookup(InodeId::ROOT, OsStr::new("d")),
            Some(id)
        );
        let recorded = fixture.notify.recorded();
        assert!(recorded.contains(&Invalidation::Entry {
            parent: INodeNo::ROOT,
            name: OsStr::new("d").to_os_string(),
        }));
        assert!(
            recorded
                .iter()
                .any(|event| matches!(event, Invalidation::Inode { .. }))
        );

        // The echo repeats the same effect.
        fixture
            .view
            .mkdir(InodeId::ROOT, OsStr::new("d"), id, 0o755)
            .unwrap();
        // A different identity for the same name is a real conflict.
        assert_eq!(
            fixture
                .view
                .mkdir(InodeId::ROOT, OsStr::new("d"), InodeId(8), 0o755),
            Err(Errno::EEXIST)
        );
    }

    /// W13b: the echo of a locally removed entry is a no-op.
    #[test]
    fn u_fuse_replay_view_unlink_is_idempotent() {
        let fixture = fixture();
        let id = InodeId(9);
        fixture
            .view
            .create(InodeId::ROOT, OsStr::new("f"), id, 0o644)
            .unwrap();
        fixture.view.unlink(InodeId::ROOT, OsStr::new("f")).unwrap();
        assert!(!fixture.tmp.path().join("f").exists());
        fixture.view.unlink(InodeId::ROOT, OsStr::new("f")).unwrap();
    }

    /// W13b: the echo of a locally applied rename is a no-op.
    #[test]
    fn u_fuse_replay_view_rename_is_idempotent() {
        let fixture = fixture();
        let id = InodeId(10);
        fixture
            .view
            .create(InodeId::ROOT, OsStr::new("a"), id, 0o644)
            .unwrap();
        fixture
            .view
            .rename(
                (InodeId::ROOT, OsStr::new("a")),
                (InodeId::ROOT, OsStr::new("b")),
            )
            .unwrap();
        assert!(fixture.tmp.path().join("b").exists());
        fixture
            .view
            .rename(
                (InodeId::ROOT, OsStr::new("a")),
                (InodeId::ROOT, OsStr::new("b")),
            )
            .unwrap();
        assert_eq!(
            fixture.view.rename(
                (InodeId::ROOT, OsStr::new("missing")),
                (InodeId::ROOT, OsStr::new("other")),
            ),
            Err(Errno::ENOENT)
        );
    }

    /// W13b: materialised data invalidates the written range and attributes.
    #[test]
    fn u_fuse_replay_view_write_invalidates_range() {
        let fixture = fixture();
        let id = InodeId(11);
        fixture
            .view
            .create(InodeId::ROOT, OsStr::new("f"), id, 0o644)
            .unwrap();
        fixture.view.write_at(id, 4, b"abc").expect("write");
        let ino = fixture.nodes.ino_of(id).expect("ino");
        let recorded = fixture.notify.recorded();
        assert!(recorded.contains(&Invalidation::Inode {
            ino: INodeNo(ino),
            offset: 4,
            len: 3,
        }));
        assert!(recorded.contains(&Invalidation::Inode {
            ino: INodeNo(ino),
            offset: 0,
            len: 0,
        }));
    }

    /// W13b: a symlink and a hard link are idempotent for the same identity.
    #[test]
    fn u_fuse_replay_view_links_are_idempotent() {
        let fixture = fixture();
        let file = InodeId(12);
        let link = InodeId(13);
        fixture
            .view
            .create(InodeId::ROOT, OsStr::new("f"), file, 0o644)
            .unwrap();
        fixture
            .view
            .symlink(InodeId::ROOT, OsStr::new("s"), link, Path::new("f"))
            .unwrap();
        fixture
            .view
            .symlink(InodeId::ROOT, OsStr::new("s"), link, Path::new("f"))
            .unwrap();
        fixture
            .view
            .link(file, InodeId::ROOT, OsStr::new("h"))
            .unwrap();
        fixture
            .view
            .link(file, InodeId::ROOT, OsStr::new("h"))
            .unwrap();
        assert!(fixture.tmp.path().join("h").exists());
    }
}
