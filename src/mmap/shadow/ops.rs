//! Filesystem operations over the shadow.
//!
//! These methods contain the pure logic the FUSE adapter calls. They do not
//! mention `fuser`; [`super::super::fuse`] converts their results to kernel
//! replies. Keeping the operations independent makes them testable without a
//! mount.

use std::os::unix::fs::FileExt;
use std::sync::Arc;

use crate::mmap::base;
use crate::mmap::db::MmTx;
use crate::mmap::types::{
    BatchId, DirAttrs, EntryKind, FileRecord, Ino, MmSeq, ROOT_INO, VersionRecord,
};

use super::db::{
    UploadPhase, VersionState, allocate_fuse, bump_dir_dirty_tx, put_shadow_dir_tx,
    put_shadow_version_tx,
};
use super::remote::{FileReadRequest, RemoteError};
use super::{
    OpenFile, Shadow, ShadowError, ShadowVersion, child_path, now_ms, now_ns, parent_path,
};

/// One inode's display attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeAttr {
    pub fuse_ino: u64,
    pub ino: Ino,
    pub version: u64,
    pub kind: EntryKind,
    pub size: u64,
    pub nlink: u32,
    pub attrs: DirAttrs,
    pub target: Option<Vec<u8>>,
}

/// One directory entry returned by `readdir`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirItem {
    pub name: String,
    pub fuse_ino: u64,
    pub kind: EntryKind,
    /// Filled for `readdirplus`; `readdir` only needs the name/type.
    pub attr: Option<NodeAttr>,
}

/// Attribute changes requested by `setattr`.
#[derive(Clone, Copy, Debug, Default)]
pub struct AttrChange {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub mtime_ns: Option<i64>,
    pub size: Option<u64>,
}

impl Shadow {
    /// Resolve one kernel inode to its foundation row.
    pub fn row(&self, fuse_ino: u64) -> Result<super::FuseRow, ShadowError> {
        self.db.fuse_row(fuse_ino)?.ok_or(ShadowError::NotFound)
    }

    /// `lookup(parent, name)`.
    pub fn lookup(&self, parent: u64, name: &str) -> Result<NodeAttr, ShadowError> {
        validate_component(name)?;
        let parent = self.row(parent)?;
        if parent.kind != EntryKind::Dir {
            return Err(ShadowError::NotDir);
        }
        self.ensure_dir(parent.ino, false)?;
        let file = self
            .db
            .file_by_name(parent.ino, name)?
            .filter(|file| !file.deleted)
            .ok_or(ShadowError::NotFound)?;
        let attr = self.node_for_file(&file)?;
        self.db.bump_nlookup(attr.fuse_ino, 1)?;
        Ok(attr)
    }

    /// `getattr(ino, fh)`.
    ///
    /// An explicit file handle wins: it names the exact version the descriptor
    /// opened, even after a remote refresh or an unlink.
    pub fn getattr(&self, fuse_ino: u64, fh: Option<u64>) -> Result<NodeAttr, ShadowError> {
        if let Some(handle) = fh.and_then(|id| self.handle(id)) {
            return self.node_for_handle(&handle);
        }
        let row = self.row(fuse_ino)?;
        if row.kind == EntryKind::Dir {
            let dir = self.db.shadow_dir(row.ino)?.ok_or(ShadowError::NotFound)?;
            return Ok(dir_attr(self, row.fuse_ino, &dir));
        }
        let file = self.db.file(row.ino)?.ok_or(ShadowError::NotFound)?;
        Ok(file_attr(row.fuse_ino, &file, row.version))
    }

    /// `readdir` / `readdirplus`.
    ///
    /// `plus` also fills attributes and bumps the kernel lookup count, as the
    /// kernel expects for `READDIRPLUS`.
    pub fn readdir(
        &self,
        fuse_ino: u64,
        offset: u64,
        plus: bool,
    ) -> Result<Vec<DirItem>, ShadowError> {
        let row = self.row(fuse_ino)?;
        if row.kind != EntryKind::Dir {
            return Err(ShadowError::NotDir);
        }
        self.ensure_dir(row.ino, false)?;
        let dir = self.db.shadow_dir(row.ino)?.ok_or(ShadowError::NotFound)?;
        let parent_ino = self.parent_ino(&dir)?;
        let mut items = Vec::new();
        let dot = DirItem {
            name: ".".to_owned(),
            fuse_ino,
            kind: EntryKind::Dir,
            attr: plus.then(|| dir_attr(self, fuse_ino, &dir)),
        };
        let mut dotdot_attr = None;
        if plus {
            if let Some(parent) = self.db.shadow_dir(parent_ino)? {
                dotdot_attr = Some(dir_attr(
                    self,
                    self.db.fuse_for(parent.record.ino, 0, EntryKind::Dir)?,
                    &parent,
                ));
            }
        }
        let dotdot = DirItem {
            name: "..".to_owned(),
            fuse_ino: self.db.fuse_for(parent_ino, 0, EntryKind::Dir)?,
            kind: EntryKind::Dir,
            attr: dotdot_attr,
        };
        items.push(dot);
        items.push(dotdot);
        for file in self.db.files(row.ino)? {
            let fuse_ino = self.db.fuse_for(file.ino, file.version, file.kind)?;
            let attr = if plus {
                let attr = if file.kind == EntryKind::Dir {
                    match self.db.shadow_dir(file.ino)? {
                        Some(child) => dir_attr(self, fuse_ino, &child),
                        None => file_attr(fuse_ino, &file, file.version),
                    }
                } else {
                    file_attr(fuse_ino, &file, file.version)
                };
                self.db.bump_nlookup(fuse_ino, 1)?;
                Some(attr)
            } else {
                None
            };
            items.push(DirItem {
                name: file.name,
                fuse_ino,
                kind: file.kind,
                attr,
            });
        }
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        if start >= items.len() {
            return Ok(Vec::new());
        }
        Ok(items.split_off(start))
    }

    /// `opendir`.
    pub fn opendir(&self, fuse_ino: u64) -> Result<(), ShadowError> {
        let row = self.row(fuse_ino)?;
        if row.kind != EntryKind::Dir {
            return Err(ShadowError::NotDir);
        }
        self.ensure_dir(row.ino, false)?;
        self.db.add_dir_handle(row.ino, 1)?;
        Ok(())
    }

    /// `releasedir`.
    pub fn releasedir(&self, fuse_ino: u64) -> Result<(), ShadowError> {
        let row = self.row(fuse_ino)?;
        if row.kind == EntryKind::Dir {
            self.db.add_dir_handle(row.ino, -1)?;
        }
        Ok(())
    }

    /// `open`.
    ///
    /// A local object is opened directly. Only a real cache miss fetches that
    /// one file; opening a file must never download every body in its
    /// directory.
    pub fn open_file(&self, fuse_ino: u64, writable: bool) -> Result<Arc<OpenFile>, ShadowError> {
        let row = self.row(fuse_ino)?;
        match row.kind {
            EntryKind::Dir => return Err(ShadowError::IsDir),
            EntryKind::Symlink => return Err(ShadowError::Invalid("cannot open a symlink")),
            EntryKind::File => {}
        }
        let mut file = self.db.file(row.ino)?.ok_or(ShadowError::NotFound)?;
        self.ensure_dir(file.dir_ino, false)?;
        file = self.db.file(row.ino)?.ok_or(ShadowError::NotFound)?;
        let version = if row.version == file.version {
            file.version
        } else {
            row.version
        };
        let path = self.layout.object_path(&row.ino, version);
        if !path.exists() {
            if version != file.version {
                return Err(ShadowError::Stale);
            }
            // A manifest-only checkout left this file's body remote. Fetch
            // just this object, not the directory's other bodies.
            self.fetch_object(&row.ino, version)?;
        }
        let file_handle = self.open_object(&row.ino, version, writable)?;
        self.db.add_open_ref(row.ino, version, 1)?;
        let handle = self.insert_handle(OpenFile {
            id: 0,
            fuse_ino,
            ino: row.ino,
            version,
            dir_ino: file.dir_ino,
            name: file.name,
            file: file_handle,
            writable,
        });
        Ok(handle)
    }

    /// `create`.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &self,
        parent: u64,
        name: &str,
        mode: u32,
        umask: u32,
        uid: u32,
        gid: u32,
        writable: bool,
    ) -> Result<(NodeAttr, Arc<OpenFile>), ShadowError> {
        validate_component(name)?;
        let parent_row = self.row(parent)?;
        if parent_row.kind != EntryKind::Dir {
            return Err(ShadowError::NotDir);
        }
        self.ensure_dir(parent_row.ino, false)?;
        if self
            .db
            .file_by_name(parent_row.ino, name)?
            .is_some_and(|file| !file.deleted)
        {
            return Err(ShadowError::Exists);
        }
        let ino = self.unique_ino()?;
        let attrs = DirAttrs {
            mode: mode & !umask & 0o7777,
            uid,
            gid,
            mtime_ns: now_ns(),
        };
        let hashes = super::content::ContentHashes::empty();
        let object = self.layout.create_object(&ino, 1)?;
        object.sync_all()?;
        drop(object);
        self.layout.link_entry(&parent_row.ino, name, &ino, 1)?;
        let file = FileRecord {
            ino,
            dir_ino: parent_row.ino,
            name: name.to_owned(),
            kind: EntryKind::File,
            attrs,
            size: 0,
            file_root: hashes.file_root,
            content_hash: Some(hashes.content_hash),
            target: None,
            version: 1,
            deleted: false,
            created_at_ms: now_ms(),
            updated_at_ms: now_ms(),
        };
        let version = VersionRecord {
            ino,
            version: 1,
            size: 0,
            file_root: hashes.file_root,
            content_hash: hashes.content_hash,
            chunk_count: 0,
            created_at_ms: now_ms(),
        };
        let fuse_ino = self.db.write(|tx| {
            let generation = bump_dir_dirty_tx(tx.conn(), &self.namespace, parent_row.ino)?;
            tx.put_file(&file)?;
            tx.put_version(&version)?;
            put_shadow_version_tx(
                tx.conn(),
                &ShadowVersion {
                    ino,
                    version: 1,
                    size: 0,
                    file_root: hashes.file_root,
                    content_hash: hashes.content_hash,
                    mtime_ns: attrs.mtime_ns,
                    dirty_gen: generation,
                    synced_size: 0,
                    synced_mtime_ns: attrs.mtime_ns,
                    open_refs: 0,
                    state: VersionState::Dirty,
                },
            )?;
            allocate_fuse(tx.conn(), ino, 1, EntryKind::File)
        })?;
        let attr = NodeAttr {
            fuse_ino,
            ino,
            version: 1,
            kind: EntryKind::File,
            size: 0,
            nlink: 1,
            attrs,
            target: None,
        };
        self.db.bump_nlookup(fuse_ino, 1)?;
        let handle = self.open_object(&ino, 1, writable)?;
        self.db.add_open_ref(ino, 1, 1)?;
        let handle = self.insert_handle(OpenFile {
            id: 0,
            fuse_ino,
            ino,
            version: 1,
            dir_ino: parent_row.ino,
            name: name.to_owned(),
            file: handle,
            writable,
        });
        Ok((attr, handle))
    }

    /// `mkdir`.
    pub fn mkdir(
        &self,
        parent: u64,
        name: &str,
        mode: u32,
        umask: u32,
        uid: u32,
        gid: u32,
    ) -> Result<NodeAttr, ShadowError> {
        validate_component(name)?;
        let parent_row = self.row(parent)?;
        if parent_row.kind != EntryKind::Dir {
            return Err(ShadowError::NotDir);
        }
        self.ensure_dir(parent_row.ino, false)?;
        if self
            .db
            .file_by_name(parent_row.ino, name)?
            .is_some_and(|file| !file.deleted)
        {
            return Err(ShadowError::Exists);
        }
        let parent_dir = self
            .db
            .shadow_dir(parent_row.ino)?
            .ok_or(ShadowError::NotFound)?;
        let ino = self.unique_ino()?;
        let attrs = DirAttrs {
            mode: mode & !umask & 0o7777,
            uid,
            gid,
            mtime_ns: now_ns(),
        };
        let path = child_path(&parent_dir.record.path, name);
        let dir = super::checkout::local_dir_record(
            &self.namespace,
            ino,
            path,
            attrs,
            parent_dir.record.base.epoch,
        );
        let entry = FileRecord {
            ino,
            dir_ino: parent_row.ino,
            name: name.to_owned(),
            kind: EntryKind::Dir,
            attrs,
            size: 0,
            file_root: base::dir_root(),
            content_hash: None,
            target: None,
            version: 0,
            deleted: false,
            created_at_ms: now_ms(),
            updated_at_ms: now_ms(),
        };
        std::fs::create_dir_all(self.layout.dir_dir(&ino))?;
        let shadow_dir = super::ShadowDir {
            record: dir.clone(),
            valid_until_ms: 0,
            dirty_gen: 0,
            uploaded_gen: 0,
            upload_state: UploadPhase::Idle,
            batch_id: None,
            lock_id: None,
            dir_handles: 0,
            bodies_checked_out: true,
            local_only: true,
            snapshot_seq: MmSeq::ZERO,
            last_checkout_ms: now_ms(),
        };
        let fuse_ino = self.db.write(|tx| {
            bump_dir_dirty_tx(tx.conn(), &self.namespace, parent_row.ino)?;
            tx.put_dir(&dir)?;
            tx.put_file(&entry)?;
            put_shadow_dir_tx(tx.conn(), &self.namespace, &shadow_dir)?;
            allocate_fuse(tx.conn(), ino, 0, EntryKind::Dir)
        })?;
        self.db.bump_nlookup(fuse_ino, 1)?;
        Ok(NodeAttr {
            fuse_ino,
            ino,
            version: 0,
            kind: EntryKind::Dir,
            size: 0,
            nlink: 2,
            attrs,
            target: None,
        })
    }

    /// `symlink`.
    pub fn symlink(
        &self,
        parent: u64,
        name: &str,
        target: &[u8],
        uid: u32,
        gid: u32,
    ) -> Result<NodeAttr, ShadowError> {
        validate_component(name)?;
        let parent_row = self.row(parent)?;
        if parent_row.kind != EntryKind::Dir {
            return Err(ShadowError::NotDir);
        }
        self.ensure_dir(parent_row.ino, false)?;
        if self
            .db
            .file_by_name(parent_row.ino, name)?
            .is_some_and(|file| !file.deleted)
        {
            return Err(ShadowError::Exists);
        }
        let ino = self.unique_ino()?;
        let attrs = DirAttrs {
            mode: 0o777,
            uid,
            gid,
            mtime_ns: now_ns(),
        };
        let root = base::symlink_root(target);
        let content_hash = *blake3::hash(target).as_bytes();
        let file = FileRecord {
            ino,
            dir_ino: parent_row.ino,
            name: name.to_owned(),
            kind: EntryKind::Symlink,
            attrs,
            size: target.len() as u64,
            file_root: root,
            content_hash: None,
            target: Some(target.to_vec()),
            version: 1,
            deleted: false,
            created_at_ms: now_ms(),
            updated_at_ms: now_ms(),
        };
        let version = VersionRecord {
            ino,
            version: 1,
            size: target.len() as u64,
            file_root: root,
            content_hash,
            chunk_count: 0,
            created_at_ms: now_ms(),
        };
        let fuse_ino = self.db.write(|tx| {
            let generation = bump_dir_dirty_tx(tx.conn(), &self.namespace, parent_row.ino)?;
            tx.put_file(&file)?;
            tx.put_version(&version)?;
            put_shadow_version_tx(
                tx.conn(),
                &ShadowVersion {
                    ino,
                    version: 1,
                    size: target.len() as u64,
                    file_root: root,
                    content_hash,
                    mtime_ns: attrs.mtime_ns,
                    dirty_gen: generation,
                    synced_size: target.len() as u64,
                    synced_mtime_ns: attrs.mtime_ns,
                    open_refs: 0,
                    state: VersionState::Dirty,
                },
            )?;
            allocate_fuse(tx.conn(), ino, 1, EntryKind::Symlink)
        })?;
        self.db.bump_nlookup(fuse_ino, 1)?;
        Ok(NodeAttr {
            fuse_ino,
            ino,
            version: 1,
            kind: EntryKind::Symlink,
            size: target.len() as u64,
            nlink: 1,
            attrs,
            target: Some(target.to_vec()),
        })
    }

    /// `unlink`.
    pub fn unlink(&self, parent: u64, name: &str) -> Result<(), ShadowError> {
        validate_component(name)?;
        let parent_row = self.row(parent)?;
        if parent_row.kind != EntryKind::Dir {
            return Err(ShadowError::NotDir);
        }
        self.ensure_dir(parent_row.ino, false)?;
        let file = self
            .db
            .file_by_name(parent_row.ino, name)?
            .filter(|file| !file.deleted)
            .ok_or(ShadowError::NotFound)?;
        if file.kind == EntryKind::Dir {
            return Err(ShadowError::IsDir);
        }
        let mut tombstone = file.clone();
        tombstone.deleted = true;
        tombstone.updated_at_ms = now_ms();
        // The link is removed before the row, so a crash can only leave a
        // tombstone that the next checkout reconciles.
        self.layout.unlink_entry(&parent_row.ino, name)?;
        self.db.write(|tx| {
            bump_dir_dirty_tx(tx.conn(), &self.namespace, parent_row.ino)?;
            tx.put_file(&tombstone)?;
            tx.conn().execute(
                "UPDATE shadow_versions SET state = 'deleted'
                 WHERE ino = ?1 AND version = ?2",
                rusqlite::params![
                    file.ino.as_slice(),
                    i64::try_from(file.version)
                        .map_err(|_| ShadowError::Invalid("version does not fit i64"))?
                ],
            )?;
            Ok(())
        })?;
        self.collect_garbage().ok();
        Ok(())
    }

    /// `rmdir`.
    pub fn rmdir(&self, parent: u64, name: &str) -> Result<(), ShadowError> {
        validate_component(name)?;
        let parent_row = self.row(parent)?;
        if parent_row.kind != EntryKind::Dir {
            return Err(ShadowError::NotDir);
        }
        self.ensure_dir(parent_row.ino, false)?;
        let file = self
            .db
            .file_by_name(parent_row.ino, name)?
            .filter(|file| !file.deleted)
            .ok_or(ShadowError::NotFound)?;
        if file.kind != EntryKind::Dir {
            return Err(ShadowError::NotDir);
        }
        if !self.db.files(file.ino)?.is_empty() {
            return Err(ShadowError::NotEmpty);
        }
        let child = self.db.shadow_dir(file.ino)?.ok_or(ShadowError::NotFound)?;
        if child.dir_handles > 0 {
            return Err(ShadowError::Busy);
        }
        self.db.write(|tx| {
            bump_dir_dirty_tx(tx.conn(), &self.namespace, parent_row.ino)?;
            tx.delete_file(file.ino)?;
            tx.delete_dir(file.ino)?;
            tx.conn().execute(
                "DELETE FROM shadow_dirs WHERE dir_ino = ?1",
                rusqlite::params![file.ino.as_slice()],
            )?;
            Ok(())
        })?;
        let _ = std::fs::remove_dir_all(self.layout.dir_dir(&file.ino));
        Ok(())
    }

    /// `rename` inside one directory. Cross-directory rename is `EXDEV`.
    pub fn rename(
        &self,
        parent: u64,
        name: &str,
        new_parent: u64,
        new_name: &str,
        noreplace: bool,
    ) -> Result<(), ShadowError> {
        validate_component(name)?;
        validate_component(new_name)?;
        let old_parent = self.row(parent)?;
        let target_parent = self.row(new_parent)?;
        if old_parent.kind != EntryKind::Dir || target_parent.kind != EntryKind::Dir {
            return Err(ShadowError::NotDir);
        }
        if old_parent.ino != target_parent.ino {
            return Err(ShadowError::CrossDevice);
        }
        self.ensure_dir(old_parent.ino, false)?;
        let source = self
            .db
            .file_by_name(old_parent.ino, name)?
            .filter(|file| !file.deleted)
            .ok_or(ShadowError::NotFound)?;
        let target = self
            .db
            .file_by_name(old_parent.ino, new_name)?
            .filter(|file| !file.deleted);
        if let Some(target) = &target {
            if noreplace {
                return Err(ShadowError::Exists);
            }
            if source.kind == EntryKind::Dir && target.kind != EntryKind::Dir {
                return Err(ShadowError::NotDir);
            }
            if source.kind != EntryKind::Dir && target.kind == EntryKind::Dir {
                return Err(ShadowError::IsDir);
            }
            if target.kind == EntryKind::Dir && !self.db.files(target.ino)?.is_empty() {
                return Err(ShadowError::NotEmpty);
            }
        }
        if name == new_name {
            return Ok(());
        }

        if source.kind != EntryKind::Dir {
            let old_link = self.layout.entry_path(&old_parent.ino, name);
            let new_link = self.layout.entry_path(&old_parent.ino, new_name);
            std::fs::rename(&old_link, &new_link)?;
        }

        let mut moved = source.clone();
        moved.name = new_name.to_owned();
        moved.updated_at_ms = now_ms();
        let old_dir_path = if source.kind == EntryKind::Dir {
            self.db.shadow_dir(source.ino)?.map(|dir| dir.record.path)
        } else {
            None
        };
        let parent_path = self
            .db
            .shadow_dir(old_parent.ino)?
            .ok_or(ShadowError::NotFound)?
            .record
            .path;
        let new_path = child_path(&parent_path, new_name);
        self.db.write(|tx| {
            bump_dir_dirty_tx(tx.conn(), &self.namespace, old_parent.ino)?;
            if let Some(target) = &target {
                tx.delete_file(target.ino)?;
                if target.kind == EntryKind::Dir {
                    tx.delete_dir(target.ino)?;
                }
            }
            tx.put_file(&moved)?;
            if let Some(old_path) = old_dir_path.as_deref() {
                rewrite_subtree_paths(tx, &self.namespace, old_path, &new_path)?;
            }
            Ok(())
        })?;
        Ok(())
    }

    /// `readlink`.
    pub fn readlink(&self, fuse_ino: u64) -> Result<Vec<u8>, ShadowError> {
        let row = self.row(fuse_ino)?;
        if row.kind != EntryKind::Symlink {
            return Err(ShadowError::Invalid("not a symlink"));
        }
        let file = self.db.file(row.ino)?.ok_or(ShadowError::NotFound)?;
        file.target
            .ok_or(ShadowError::Invalid("symlink has no target"))
    }

    /// `read`.
    pub fn read(
        &self,
        fuse_ino: u64,
        fh: Option<u64>,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, ShadowError> {
        let (ino, version) = if let Some(handle) = fh.and_then(|id| self.handle(id)) {
            (handle.ino, handle.version)
        } else {
            let row = self.row(fuse_ino)?;
            if row.kind != EntryKind::File {
                return Err(ShadowError::IsDir);
            }
            (row.ino, row.version)
        };
        let file = self.open_object(&ino, version, false)?;
        let mut buffer = vec![0u8; size as usize];
        let read = file.read_at(&mut buffer, offset)?;
        buffer.truncate(read);
        Ok(buffer)
    }

    /// `write`.
    pub fn write(
        &self,
        fuse_ino: u64,
        fh: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<u32, ShadowError> {
        let handle = match self.handle(fh) {
            Some(handle) => handle,
            None => {
                // A writeback-cache write may arrive after `release`. The
                // kernel still owns a lookup reference, so the version and
                // object remain live.
                let row = self.row(fuse_ino)?;
                let file = self.db.file(row.ino)?.ok_or(ShadowError::NotFound)?;
                let object = self.open_object(&row.ino, row.version, true)?;
                Arc::new(OpenFile {
                    id: fh,
                    fuse_ino,
                    ino: row.ino,
                    version: row.version,
                    dir_ino: file.dir_ino,
                    name: file.name,
                    file: object,
                    writable: true,
                })
            }
        };
        if !handle.writable {
            return Err(ShadowError::ReadOnly);
        }
        let lock = self.version_lock(handle.ino, handle.version);
        let _guard = super::lock(&lock);
        handle.file.write_at(data, offset)?;
        let size = offset.saturating_add(data.len() as u64);
        let metadata = handle.file.metadata()?;
        let current_size = metadata.len();
        let mtime_ns = now_ns();
        let mut file = self.db.file(handle.ino)?.ok_or(ShadowError::NotFound)?;
        file.size = current_size.max(size);
        file.attrs.mtime_ns = mtime_ns;
        file.updated_at_ms = now_ms();
        let file_root = file.file_root;
        let content_hash = file.content_hash.unwrap_or_else(|| {
            *blake3::hash(file.target.as_deref().unwrap_or_default()).as_bytes()
        });
        self.db.record_mutation(
            handle.dir_ino,
            &file,
            file.size,
            mtime_ns,
            file_root,
            content_hash,
        )?;
        Ok(data.len() as u32)
    }

    /// `setattr`, including `truncate`.
    pub fn setattr(
        &self,
        fuse_ino: u64,
        fh: Option<u64>,
        change: AttrChange,
    ) -> Result<NodeAttr, ShadowError> {
        let row = self.row(fuse_ino)?;
        if row.kind == EntryKind::Dir {
            if change.size.is_some() {
                return Err(ShadowError::IsDir);
            }
            let mut dir = self.db.shadow_dir(row.ino)?.ok_or(ShadowError::NotFound)?;
            if let Some(mode) = change.mode {
                dir.record.attrs.mode = mode & 0o7777;
            }
            if let Some(uid) = change.uid {
                dir.record.attrs.uid = uid;
            }
            if let Some(gid) = change.gid {
                dir.record.attrs.gid = gid;
            }
            if let Some(mtime_ns) = change.mtime_ns {
                dir.record.attrs.mtime_ns = mtime_ns;
            }
            self.db.put_dir(&dir.record)?;
            self.db.bump_dir_dirty(row.ino)?;
            return Ok(dir_attr(self, fuse_ino, &dir));
        }

        let mut file = self.db.file(row.ino)?.ok_or(ShadowError::NotFound)?;
        if file.kind == EntryKind::Symlink && change.size.is_some() {
            return Err(ShadowError::Invalid("cannot truncate a symlink"));
        }
        if let Some(size) = change.size {
            match fh.and_then(|id| self.handle(id)) {
                Some(handle) => {
                    handle.file.set_len(size)?;
                    handle.file.sync_all()?;
                }
                None => {
                    let object = self.open_object(&row.ino, row.version, true)?;
                    object.set_len(size)?;
                    object.sync_all()?;
                }
            }
            file.size = size;
            file.attrs.mtime_ns = now_ns();
            file.updated_at_ms = now_ms();
            let root = file.file_root;
            let hash = file
                .content_hash
                .unwrap_or_else(|| *blake3::hash(b"").as_bytes());
            self.db
                .record_mutation(file.dir_ino, &file, size, file.attrs.mtime_ns, root, hash)?;
        } else {
            if let Some(mode) = change.mode {
                file.attrs.mode = mode & 0o7777;
            }
            if let Some(uid) = change.uid {
                file.attrs.uid = uid;
            }
            if let Some(gid) = change.gid {
                file.attrs.gid = gid;
            }
            if let Some(mtime_ns) = change.mtime_ns {
                file.attrs.mtime_ns = mtime_ns;
            }
            file.updated_at_ms = now_ms();
            self.db
                .record_metadata(file.dir_ino, &file, file.attrs.mtime_ns)?;
        }
        let file = self.db.file(row.ino)?.ok_or(ShadowError::NotFound)?;
        Ok(file_attr(fuse_ino, &file, file.version))
    }

    /// `flush`: persist metadata and release this owner's POSIX locks.
    ///
    /// No upload happens here. `close` must not publish a half-finished
    /// directory.
    pub fn flush(&self, fh: u64, lock_owner: Option<u64>) -> Result<(), ShadowError> {
        let handle = self.handle(fh).ok_or(ShadowError::NotFound)?;
        if let Some(owner) = lock_owner {
            self.locks.release_owner(handle.ino, owner);
        }
        handle.file.sync_data()?;
        Ok(())
    }

    /// `release`: drop one reference. Nothing is uploaded.
    pub fn release(&self, fh: u64) -> Result<(), ShadowError> {
        let Some(handle) = self.remove_handle(fh) else {
            return Ok(());
        };
        self.db.add_open_ref(handle.ino, handle.version, -1)?;
        self.collect_garbage().ok();
        Ok(())
    }

    /// `forget`: drop kernel lookup references.
    pub fn forget(&self, fuse_ino: u64, nlookup: u64) -> Result<(), ShadowError> {
        if fuse_ino == Self::root_ino() {
            return Ok(());
        }
        self.db
            .bump_nlookup(fuse_ino, -i64::try_from(nlookup).unwrap_or(i64::MAX))?;
        self.collect_garbage().ok();
        Ok(())
    }

    /// `getlk`.
    pub fn getlk(
        &self,
        fuse_ino: u64,
        owner: u64,
        start: u64,
        end: u64,
        typ: i32,
    ) -> Result<Option<super::RangeLock>, ShadowError> {
        let row = self.row(fuse_ino)?;
        self.locks.getlk(row.ino, owner, start, end, typ)
    }

    /// `setlk`.
    #[allow(clippy::too_many_arguments)]
    pub fn setlk(
        &self,
        fuse_ino: u64,
        owner: u64,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
        sleep: bool,
    ) -> Result<(), ShadowError> {
        let row = self.row(fuse_ino)?;
        self.locks
            .setlk(row.ino, owner, start, end, typ, pid, sleep)
    }

    /// Take a local `flock` on one shadow object.
    pub fn flock(
        &self,
        fuse_ino: u64,
        exclusive: bool,
        nonblocking: bool,
    ) -> Result<(), ShadowError> {
        let row = self.row(fuse_ino)?;
        let file = self.layout.open_object(&row.ino, row.version)?;
        if exclusive {
            super::flock_exclusive(&file, nonblocking)?;
        } else {
            super::flock_shared(&file, nonblocking)?;
        }
        Ok(())
    }

    /// `access`: the mount does not enforce credentials; existence is enough.
    pub fn access(&self, fuse_ino: u64) -> Result<(), ShadowError> {
        self.row(fuse_ino).map(|_| ())
    }

    /// `lseek`. The shadow stores regular files contiguously, so `SEEK_DATA`
    /// succeeds before EOF and `SEEK_HOLE` returns EOF.
    pub fn lseek(&self, fuse_ino: u64, offset: i64, whence: i32) -> Result<i64, ShadowError> {
        let attr = self.getattr(fuse_ino, None)?;
        if attr.kind != EntryKind::File {
            return Err(ShadowError::IsDir);
        }
        let size = i64::try_from(attr.size).unwrap_or(i64::MAX);
        match whence {
            libc::SEEK_SET | libc::SEEK_CUR => Ok(offset.max(0)),
            libc::SEEK_END => Ok(size),
            libc::SEEK_DATA => {
                if offset >= size {
                    Err(ShadowError::NotFound)
                } else {
                    Ok(offset.max(0))
                }
            }
            libc::SEEK_HOLE => Ok(size),
            _ => Err(ShadowError::Invalid("unsupported seek mode")),
        }
    }

    /// The directory inode that owns one child.
    pub fn parent_ino(&self, dir: &super::ShadowDir) -> Result<Ino, ShadowError> {
        let parent = parent_path(&dir.record.path);
        if parent == dir.record.path {
            return Ok(dir.record.ino);
        }
        self.db
            .shadow_dir_by_path(parent)?
            .map(|dir| dir.record.ino)
            .ok_or(ShadowError::NotFound)
    }

    fn node_for_file(&self, file: &FileRecord) -> Result<NodeAttr, ShadowError> {
        let fuse_ino = self.db.fuse_for(file.ino, file.version, file.kind)?;
        if file.kind == EntryKind::Dir {
            if let Some(dir) = self.db.shadow_dir(file.ino)? {
                return Ok(dir_attr(self, fuse_ino, &dir));
            }
        }
        Ok(file_attr(fuse_ino, file, file.version))
    }

    fn unique_ino(&self) -> Result<Ino, ShadowError> {
        loop {
            let ino = random_ino();
            if !self.db.ino_exists(ino)? {
                return Ok(ino);
            }
        }
    }

    fn node_for_handle(&self, handle: &OpenFile) -> Result<NodeAttr, ShadowError> {
        let mut file = self.db.file(handle.ino)?.ok_or(ShadowError::NotFound)?;
        file.size = handle.file.metadata()?.len();
        let version = self
            .db
            .shadow_version(handle.ino, handle.version)?
            .map_or(handle.version, |version| version.version);
        Ok(file_attr(handle.fuse_ino, &file, version))
    }

    fn open_object(
        &self,
        ino: &Ino,
        version: u64,
        writable: bool,
    ) -> Result<std::fs::File, ShadowError> {
        let path = self.layout.object_path(ino, version);
        if !path.exists() {
            // Last resort for a metadata-only snapshot: ask for ranges and
            // rebuild the object. The common path is checkout bodies.
            self.fetch_object(ino, version)?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        if writable {
            options.write(true);
        }
        Ok(options.open(path)?)
    }

    fn fetch_object(&self, ino: &Ino, version: u64) -> Result<(), ShadowError> {
        let file = self.db.file(*ino)?.ok_or(ShadowError::NotFound)?;
        if file.version != version {
            return Err(ShadowError::Stale);
        }
        let dir = self
            .db
            .shadow_dir(file.dir_ino)?
            .ok_or(ShadowError::NotFound)?;
        let mut offset = 0u64;
        let mut data = Vec::new();
        while offset < file.size {
            let want =
                u32::try_from((file.size - offset).min(8 * 1024 * 1024)).unwrap_or(8 * 1024 * 1024);
            let range = self.remote.file_read(&FileReadRequest {
                dir_path: dir.record.path.clone(),
                dir_ino: file.dir_ino,
                name: file.name.clone(),
                ino: file.ino,
                file_root: file.file_root,
                offset,
                len: want,
            })?;
            if range.offset != offset || range.bytes.is_empty() {
                return Err(ShadowError::Remote(RemoteError::Internal(
                    "file read returned a non-contiguous range".to_owned(),
                )));
            }
            if *blake3::hash(&range.bytes).as_bytes() != range.range_hash {
                return Err(ShadowError::Remote(RemoteError::Internal(
                    "file read range hash mismatch".to_owned(),
                )));
            }
            data.extend_from_slice(&range.bytes);
            offset = offset.saturating_add(range.bytes.len() as u64);
        }
        if data.len() as u64 != file.size {
            return Err(ShadowError::Remote(RemoteError::Internal(
                "file read returned a short object".to_owned(),
            )));
        }
        if blake3::hash(&data).as_bytes() != &file.content_hash.unwrap_or([0; 32]) {
            return Err(ShadowError::Invalid("file read content hash mismatch"));
        }
        let batch = BatchId::new_random();
        let staging = self.layout.create_staging(&file.dir_ino, batch)?;
        let staged = staging.join("range.body");
        let result: Result<(), ShadowError> = (|| {
            super::content::write_staged(&staged, &data)?;
            super::content::publish_staged(&self.layout, ino, version, &staged)?;
            self.layout
                .link_entry(&file.dir_ino, &file.name, ino, version)?;
            self.db.mark_version_clean(*ino, version)?;
            Ok(())
        })();
        let _ = std::fs::remove_dir_all(&staging);
        result?;
        Ok(())
    }
}

fn validate_component(name: &str) -> Result<(), ShadowError> {
    crate::mmap::types::validate_name(name).map_err(ShadowError::Invalid)
}

fn random_ino() -> Ino {
    loop {
        let ino = rand::random::<[u8; 16]>();
        if ino != ROOT_INO && ino != [0; 16] {
            return ino;
        }
    }
}

fn file_attr(fuse_ino: u64, file: &FileRecord, version: u64) -> NodeAttr {
    NodeAttr {
        fuse_ino,
        ino: file.ino,
        version,
        kind: file.kind,
        size: file.size,
        nlink: 1,
        attrs: file.attrs,
        target: file.target.clone(),
    }
}

fn dir_attr(_shadow: &Shadow, fuse_ino: u64, dir: &super::ShadowDir) -> NodeAttr {
    NodeAttr {
        fuse_ino,
        ino: dir.record.ino,
        version: 0,
        kind: EntryKind::Dir,
        size: 0,
        nlink: 2,
        attrs: dir.record.attrs,
        target: None,
    }
}

fn rewrite_subtree_paths(
    tx: &crate::mmap::WriteTx<'_>,
    namespace: &str,
    old_prefix: &str,
    new_prefix: &str,
) -> Result<(), ShadowError> {
    tx.conn().execute(
        "UPDATE mm_dirs
         SET path = ?3 || substr(path, length(?2) + 1), updated_at_ms = ?4
         WHERE namespace = ?1
           AND (path = ?2 OR path LIKE ?2 || '/%')",
        rusqlite::params![namespace, old_prefix, new_prefix, now_ms(),],
    )?;
    tx.conn().execute(
        "UPDATE mm_dir_versions
         SET dir_path = ?3 || substr(dir_path, length(?2) + 1), updated_at_ms = ?4
         WHERE namespace = ?1
           AND (dir_path = ?2 OR dir_path LIKE ?2 || '/%')",
        rusqlite::params![namespace, old_prefix, new_prefix, now_ms(),],
    )?;
    Ok(())
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn component_validation_rejects_separators_and_dots() {
        assert!(validate_component("ok").is_ok());
        assert!(validate_component("a/b").is_err());
        assert!(validate_component(".").is_err());
        assert!(validate_component("..").is_err());
        assert!(validate_component("").is_err());
    }
}
