//! Local-first mutations: FUSE writes become one SQLite transaction plus one
//! durable outbox row.
//!
//! Every method here commits before it returns. The network is not consulted;
//! a failed uplink leaves the operation in the outbox, and a reconnect
//! resends it. The server's echo is matched by `op_id` and only marks the row
//! `acked`; it never applies the local effect a second time.
//!
//! # Identity
//!
//! A create derives its inode from the operation id: `ino = op_id`. The
//! server uses the same rule, so no inode field has to travel on the wire.
//!
//! # Chunk list shape
//!
//! `object_chunks` is always contiguous from chunk 0 to `ceil(size/64KiB)-1`,
//! every non-final chunk is exactly 64 KiB, and `size` is the sum of lengths.
//! A write that leaves a hole is zero-filled, because the wire protocol has no
//! sparse representation.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use rusqlite::{OptionalExtension, params};

use super::db::{CHUNK, ClientDb, DbError, Ino, join_path, now_ns};
use crate::store::Errno;
use crate::store::sqlite::{
    self, ChunkRef, EventPayload, Object, ObjectKind, ROOT_INO, WriteTx,
};

/// Attributes a create carries into the event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateAttrs {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

impl CreateAttrs {
    pub const fn new(mode: u32, uid: u32, gid: u32) -> Self {
        Self { mode, uid, gid }
    }
}

/// A partial attribute update. `None` leaves a field unchanged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttrChange {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub mtime_ns: Option<i64>,
    pub size: Option<u64>,
}

/// `rename(2)` flags this implementation understands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RenameFlags {
    /// Fail when the target exists (`RENAME_NOREPLACE`).
    pub noreplace: bool,
    /// Exchange two entries (`RENAME_EXCHANGE`); not supported.
    pub exchange: bool,
}

impl ClientDb {
    /// Create a regular file.
    pub fn create_file(
        &self,
        parent: Ino,
        name: &OsStr,
        attrs: CreateAttrs,
    ) -> Result<Object, DbError> {
        self.create_object(parent, name, attrs, ObjectKind::File, None)
    }

    /// Create a directory.
    pub fn create_dir(
        &self,
        parent: Ino,
        name: &OsStr,
        attrs: CreateAttrs,
    ) -> Result<Object, DbError> {
        self.create_object(parent, name, attrs, ObjectKind::Dir, None)
    }

    /// Create a symbolic link.
    pub fn create_symlink(
        &self,
        parent: Ino,
        name: &OsStr,
        target: &OsStr,
        attrs: CreateAttrs,
    ) -> Result<Object, DbError> {
        let target = target.as_bytes().to_vec();
        if target.is_empty() || target.contains(&0) || target.len() > 4096 {
            return Err(Errno::EINVAL.into());
        }
        self.create_object(parent, name, attrs, ObjectKind::Symlink, Some(target))
    }

    fn create_object(
        &self,
        parent: Ino,
        name: &OsStr,
        attrs: CreateAttrs,
        kind: ObjectKind,
        target: Option<Vec<u8>>,
    ) -> Result<Object, DbError> {
        let name_text = validate_name(name)?;
        let mtime_ns = now_ns();
        self.write(|tx| {
            let parent_object = Self::object_in(tx, parent)?
                .ok_or(DbError::Errno(Errno::ENOENT))?;
            if parent_object.deleted || !parent_object.kind.is_dir() {
                return Err(DbError::Errno(Errno::ENOTDIR));
            }
            if Self::name_in(tx, parent, &name_text)?.is_some() {
                return Err(DbError::Errno(Errno::EEXIST));
            }
            let parent_path = Self::path_in(tx, parent)?;
            let path = join_path(&parent_path, &name_text);
            let seq = Self::next_local_seq(tx)?;
            let op_id = alloc_op_id();
            let ino = op_id;
            let file_root = match kind {
                ObjectKind::File => sqlite::file_root(ObjectKind::File, None, &[]),
                ObjectKind::Dir => sqlite::file_root(ObjectKind::Dir, None, &[]),
                ObjectKind::Symlink => {
                    sqlite::file_root(ObjectKind::Symlink, target.as_deref(), &[])
                }
                other => return Err(DbError::Corrupt(unsupported_kind(other))),
            };
            let size = target.as_ref().map_or(0, |target| target.len() as u64);
            let object = Object {
                ino,
                kind,
                mode: attrs.mode,
                uid: attrs.uid,
                gid: attrs.gid,
                mtime_ns,
                size,
                file_root,
                block_count: 0,
                target: target.clone(),
                nlink: if kind.is_dir() { 2 } else { 1 },
                deleted: false,
                created_seq: seq,
                updated_seq: seq,
            };
            tx.put_object(&object)?;
            tx.put_name(parent, &name_text, ino, &path)?;
            if kind.is_dir() {
                bump_nlink(tx, parent, 1)?;
            }
            Self::next_fuse_ino(tx, ino)?;
            let payload = match kind {
                ObjectKind::File => EventPayload::CreateFile {
                    ino,
                    mode: attrs.mode,
                    uid: attrs.uid,
                    gid: attrs.gid,
                    mtime_ns,
                    file_root,
                },
                ObjectKind::Dir => EventPayload::CreateDir {
                    ino,
                    mode: attrs.mode,
                    uid: attrs.uid,
                    gid: attrs.gid,
                    mtime_ns,
                    file_root,
                },
                ObjectKind::Symlink => EventPayload::Symlink {
                    ino,
                    mode: attrs.mode,
                    uid: attrs.uid,
                    gid: attrs.gid,
                    mtime_ns,
                    target: target.unwrap_or_default(),
                    file_root,
                },
                other => return Err(DbError::Corrupt(unsupported_kind(other))),
            };
            Self::enqueue(tx, op_id, &payload, Some(&path), None, &[], seq)?;
            Ok(object)
        })
    }

    /// Add a hard link.
    pub fn link(&self, ino: Ino, newparent: Ino, newname: &OsStr) -> Result<Object, DbError> {
        let name_text = validate_name(newname)?;
        self.write(|tx| {
            let object = Self::object_in(tx, ino)?.ok_or(DbError::Errno(Errno::ENOENT))?;
            if object.deleted {
                return Err(DbError::Errno(Errno::ENOENT));
            }
            if object.kind.is_dir() {
                return Err(DbError::Errno(Errno::EPERM));
            }
            let parent = Self::object_in(tx, newparent)?
                .ok_or(DbError::Errno(Errno::ENOENT))?;
            if !parent.kind.is_dir() || parent.deleted {
                return Err(DbError::Errno(Errno::ENOTDIR));
            }
            if Self::name_in(tx, newparent, &name_text)?.is_some() {
                return Err(DbError::Errno(Errno::EEXIST));
            }
            let parent_path = Self::path_in(tx, newparent)?;
            let path = join_path(&parent_path, &name_text);
            // Capture the existing name before inserting the new one; the
            // wire convention is F_PATH = new path, F_TARGET = existing path.
            let target_path = Self::path_in(tx, ino)?;
            let seq = Self::next_local_seq(tx)?;
            let op_id = alloc_op_id();
            tx.put_name(newparent, &name_text, ino, &path)?;
            bump_nlink(tx, ino, 1)?;
            Self::next_fuse_ino(tx, ino)?;
            let mut linked = object;
            linked.nlink = linked.nlink.saturating_add(1);
            Self::enqueue(
                tx,
                op_id,
                &EventPayload::Link { ino },
                Some(&target_path),
                Some(&path),
                &[],
                seq,
            )?;
            Ok(linked)
        })
    }

    /// Remove one non-directory entry.
    pub fn unlink(&self, parent: Ino, name: &OsStr) -> Result<(), DbError> {
        let name_text = validate_name(name)?;
        self.write(|tx| {
            let object = Self::remove_name(tx, parent, &name_text)?;
            if object.kind.is_dir() {
                return Err(DbError::Errno(Errno::EISDIR));
            }
            let seq = Self::next_local_seq(tx)?;
            let op_id = alloc_op_id();
            let path = join_path(&Self::path_in(tx, parent)?, &name_text);
            Self::enqueue(
                tx,
                op_id,
                &EventPayload::Unlink { ino: object.ino },
                Some(&path),
                None,
                &[],
                seq,
            )?;
            Ok(())
        })
    }

    /// Remove one empty directory.
    pub fn rmdir(&self, parent: Ino, name: &OsStr) -> Result<(), DbError> {
        let name_text = validate_name(name)?;
        self.write(|tx| {
            let entry = Self::name_in(tx, parent, &name_text)?
                .ok_or(DbError::Errno(Errno::ENOENT))?;
            let object = Self::object_in(tx, entry)?
                .ok_or(DbError::Errno(Errno::ENOENT))?;
            if !object.kind.is_dir() {
                return Err(DbError::Errno(Errno::ENOTDIR));
            }
            let children: i64 = tx.conn().query_row(
                "SELECT COUNT(*) FROM names WHERE parent = ?1",
                [object.ino.as_slice()],
                |row| row.get(0),
            )?;
            if children != 0 {
                return Err(DbError::Errno(Errno::ENOTEMPTY));
            }
            let path = join_path(&Self::path_in(tx, parent)?, &name_text);
            let seq = Self::next_local_seq(tx)?;
            let op_id = alloc_op_id();
            Self::remove_name(tx, parent, &name_text)?;
            Self::enqueue(
                tx,
                op_id,
                &EventPayload::Rmdir { ino: object.ino },
                Some(&path),
                None,
                &[],
                seq,
            )?;
            Ok(())
        })
    }

    /// Rename one entry.
    pub fn rename(
        &self,
        old_parent: Ino,
        old_name: &OsStr,
        new_parent: Ino,
        new_name: &OsStr,
        flags: RenameFlags,
    ) -> Result<(), DbError> {
        if flags.exchange {
            return Err(Errno::EOPNOTSUPP.into());
        }
        let old_text = validate_name(old_name)?;
        let new_text = validate_name(new_name)?;
        self.write(|tx| {
            let entry = Self::name_in(tx, old_parent, &old_text)?
                .ok_or(DbError::Errno(Errno::ENOENT))?;
            let object = Self::object_in(tx, entry)?
                .ok_or(DbError::Errno(Errno::ENOENT))?;
            let new_parent_object = Self::object_in(tx, new_parent)?
                .ok_or(DbError::Errno(Errno::ENOENT))?;
            if !new_parent_object.kind.is_dir() || new_parent_object.deleted {
                return Err(DbError::Errno(Errno::ENOTDIR));
            }
            let old_path = Self::path_in(tx, entry)?;
            let new_parent_path = Self::path_in(tx, new_parent)?;
            let new_path = join_path(&new_parent_path, &new_text);

            if object.kind.is_dir() {
                let prefix = format!("{old_path}/");
                if new_path.starts_with(&prefix) {
                    return Err(Errno::EINVAL.into());
                }
            }

            let target = Self::name_in(tx, new_parent, &new_text)?;
            if target == Some(object.ino) && old_parent == new_parent && old_text == new_text {
                return Ok(());
            }
            if let Some(target_ino) = target {
                if flags.noreplace {
                    return Err(Errno::EEXIST.into());
                }
                if target_ino != object.ino {
                    let target_object = Self::object_in(tx, target_ino)?
                        .ok_or(DbError::Errno(Errno::ENOENT))?;
                    if target_object.kind.is_dir() {
                        let children: i64 = tx.conn().query_row(
                            "SELECT COUNT(*) FROM names WHERE parent = ?1",
                            [target_ino.as_slice()],
                            |row| row.get(0),
                        )?;
                        if children != 0 {
                            return Err(DbError::Errno(Errno::ENOTEMPTY));
                        }
                    } else if object.kind.is_dir() {
                        return Err(DbError::Errno(Errno::ENOTDIR));
                    }
                    Self::remove_name(tx, new_parent, &new_text)?;
                }
            }

            let seq = Self::next_local_seq(tx)?;
            let op_id = alloc_op_id();
            // Detach the old name without touching the object's link count;
            // it is re-attached below.
            tx.delete_name(old_parent, &old_text)?;
            if object.kind.is_dir() {
                Self::rewrite_subtree_paths(tx, &old_path, &new_path)?;
                if old_parent != new_parent {
                    bump_nlink(tx, old_parent, -1)?;
                    bump_nlink(tx, new_parent, 1)?;
                }
            }
            tx.put_name(new_parent, &new_text, object.ino, &new_path)?;
            Self::next_fuse_ino(tx, object.ino)?;
            Self::enqueue(
                tx,
                op_id,
                &EventPayload::Rename { ino: object.ino },
                Some(&old_path),
                Some(&new_path),
                &[],
                seq,
            )?;
            Ok(())
        })
    }

    /// Write at an offset. Returns the number of bytes written.
    pub fn write_at(&self, ino: Ino, off: u64, data: &[u8]) -> Result<usize, DbError> {
        if data.is_empty() {
            return Ok(0);
        }
        let mut db = self.lock_writer();
        let snapshot = db.read()?;
        let object = Self::object_in_read(&snapshot, ino)?
            .ok_or(DbError::Errno(Errno::ENOENT))?;
        if object.deleted {
            return Err(DbError::Errno(Errno::ENOENT));
        }
        if object.kind.is_dir() {
            return Err(DbError::Errno(Errno::EISDIR));
        }
        if !object.kind.is_file() {
            return Err(DbError::Errno(Errno::EINVAL));
        }
        let old_refs = snapshot.object_chunks(ino)?;
        let mut by_no: BTreeMap<u32, ChunkRef> =
            old_refs.iter().map(|chunk| (chunk.chunk_no, chunk.clone())).collect();
        let old_size = object.size;
        let end = off
            .checked_add(data.len() as u64)
            .ok_or(DbError::Errno(Errno::EOVERFLOW))?;
        let new_size = old_size.max(end);
        let first = off / CHUNK;
        let last = (end - 1) / CHUNK;
        let mtime_ns = now_ns();

        let tx = db.write()?;
        let mut written = Vec::new();
        for chunk_no in first..=last {
            let chunk_no_u32 = u32::try_from(chunk_no)
                .map_err(|_| DbError::Corrupt("chunk number out of range"))?;
            let chunk_start = chunk_no * CHUNK;
            let final_len = ((new_size - chunk_start).min(CHUNK)) as u32;
            let mut buffer = if chunk_no_u32 as u64 * CHUNK < old_size {
                match by_no.get(&chunk_no_u32) {
                    Some(existing) => {
                        let chunk = snapshot
                            .chunk(existing.hash)?
                            .ok_or(DbError::MissingChunk(existing.hash))?;
                        chunk
                            .data
                            .ok_or(DbError::MissingChunk(existing.hash))?
                    }
                    None => Vec::new(),
                }
            } else {
                Vec::new()
            };
            buffer.resize(final_len as usize, 0);
            let write_start = off.max(chunk_start);
            let write_end = end.min(chunk_start + CHUNK);
            if write_start < write_end {
                let from = (write_start - chunk_start) as usize;
                let to = (write_end - chunk_start) as usize;
                let src = (write_start - off) as usize;
                buffer[from..to].copy_from_slice(&data[src..src + (to - from)]);
            }
            let reference = Self::put_chunk_ref(&tx, chunk_no_u32, &buffer)?;
            by_no.insert(chunk_no_u32, reference.clone());
            written.push(reference);
        }

        let refs = Self::assemble_chunks(&tx, new_size, &by_no)?;
        let file_root = sqlite::file_root(ObjectKind::File, None, &refs);
        let mut updated = object.clone();
        updated.size = new_size;
        updated.block_count = u32::try_from(refs.len())
            .map_err(|_| DbError::Corrupt("too many chunks"))?;
        updated.file_root = file_root;
        updated.mtime_ns = mtime_ns;
        updated.updated_seq = Self::current_local_seq(&tx)?;
        tx.put_object(&updated)?;
        tx.set_object_chunks(ino, &refs)?;
        let payload = EventPayload::Write {
            ino,
            offset: off,
            len: data.len() as u64,
            size: new_size,
            file_root,
            mtime_ns,
            chunks: written.clone(),
        };
        let seq = Self::next_local_seq(&tx)?;
        let op_id = alloc_op_id();
        let path = Self::path_in(&tx, ino)?;
        Self::enqueue(&tx, op_id, &payload, Some(&path), None, &written, seq)?;
        tx.commit()?;
        Ok(data.len())
    }

    /// Truncate a regular file.
    pub fn truncate(&self, ino: Ino, size: u64) -> Result<(), DbError> {
        let mut db = self.lock_writer();
        let snapshot = db.read()?;
        let object = Self::object_in_read(&snapshot, ino)?
            .ok_or(DbError::Errno(Errno::ENOENT))?;
        if object.deleted {
            return Err(DbError::Errno(Errno::ENOENT));
        }
        if object.kind.is_dir() {
            return Err(DbError::Errno(Errno::EISDIR));
        }
        if !object.kind.is_file() {
            return Err(DbError::Errno(Errno::EINVAL));
        }
        if object.size == size {
            return Ok(());
        }
        let old_refs = snapshot.object_chunks(ino)?;
        let mut by_no: BTreeMap<u32, ChunkRef> =
            old_refs.iter().map(|chunk| (chunk.chunk_no, chunk.clone())).collect();
        let old_size = object.size;
        let mtime_ns = now_ns();

        let tx = db.write()?;
        let mut touched = Vec::new();
        if size > old_size {
            // Extend the boundary chunk with zeroes when the old size was not
            // chunk-aligned; `assemble_chunks` fills whole missing chunks.
            let chunk_no = old_size / CHUNK;
            if let Some(existing) = by_no.get(&(chunk_no as u32)).cloned() {
                let chunk = snapshot
                    .chunk(existing.hash)?
                    .ok_or(DbError::MissingChunk(existing.hash))?;
                let mut buffer = chunk
                    .data
                    .ok_or(DbError::MissingChunk(existing.hash))?;
                let final_len = ((size - chunk_no * CHUNK).min(CHUNK)) as usize;
                if buffer.len() < final_len {
                    buffer.resize(final_len, 0);
                    let reference =
                        Self::put_chunk_ref(&tx, chunk_no as u32, &buffer)?;
                    by_no.insert(chunk_no as u32, reference.clone());
                    touched.push(reference);
                }
            }
        } else {
            // Shrink: the boundary chunk keeps its prefix only.
            let chunk_no = size / CHUNK;
            if size % CHUNK != 0 {
                if let Some(existing) = by_no.get(&(chunk_no as u32)).cloned() {
                    let chunk = snapshot
                        .chunk(existing.hash)?
                        .ok_or(DbError::MissingChunk(existing.hash))?;
                    let mut buffer = chunk
                        .data
                        .ok_or(DbError::MissingChunk(existing.hash))?;
                    buffer.truncate((size - chunk_no * CHUNK) as usize);
                    let reference =
                        Self::put_chunk_ref(&tx, chunk_no as u32, &buffer)?;
                    by_no.insert(chunk_no as u32, reference.clone());
                    touched.push(reference);
                }
            }
            let keep = size.div_ceil(CHUNK) as u32;
            by_no.retain(|chunk_no, _| *chunk_no < keep);
        }
        let refs = Self::assemble_chunks(&tx, size, &by_no)?;
        let file_root = sqlite::file_root(ObjectKind::File, None, &refs);
        let mut updated = object.clone();
        updated.size = size;
        updated.block_count = u32::try_from(refs.len())
            .map_err(|_| DbError::Corrupt("too many chunks"))?;
        updated.file_root = file_root;
        updated.mtime_ns = mtime_ns;
        updated.updated_seq = Self::current_local_seq(&tx)?;
        tx.put_object(&updated)?;
        tx.set_object_chunks(ino, &refs)?;
        let payload = EventPayload::Truncate {
            ino,
            size,
            file_root,
            mtime_ns,
        };
        let seq = Self::next_local_seq(&tx)?;
        let op_id = alloc_op_id();
        let path = Self::path_in(&tx, ino)?;
        Self::enqueue(&tx, op_id, &payload, Some(&path), None, &touched, seq)?;
        tx.commit()?;
        Ok(())
    }

    /// Apply attribute changes, including a size change.
    pub fn setattr(&self, ino: Ino, change: AttrChange) -> Result<Object, DbError> {
        let object = self.getattr(ino)?;
        if let Some(size) = change.size {
            if size != object.size {
                self.truncate(ino, size)?;
            }
        }
        let mtime_ns = change.mtime_ns.unwrap_or_else(now_ns);
        self.write(|tx| {
            let mut object = Self::object_in(tx, ino)?
                .ok_or(DbError::Errno(Errno::ENOENT))?;
            if object.deleted {
                return Err(DbError::Errno(Errno::ENOENT));
            }
            let mut changed = false;
            if let Some(mode) = change.mode {
                if object.mode != mode {
                    object.mode = mode;
                    changed = true;
                }
            }
            if let Some(uid) = change.uid {
                if object.uid != uid {
                    object.uid = uid;
                    changed = true;
                }
            }
            if let Some(gid) = change.gid {
                if object.gid != gid {
                    object.gid = gid;
                    changed = true;
                }
            }
            if change.mtime_ns.is_some() && object.mtime_ns != mtime_ns {
                object.mtime_ns = mtime_ns;
                changed = true;
            }
            if !changed {
                return Ok(object);
            }
            object.updated_seq = Self::current_local_seq(tx)?;
            tx.put_object(&object)?;
            let seq = Self::next_local_seq(tx)?;
            let op_id = alloc_op_id();
            let path = Self::path_in(tx, ino)?;
            let payload = EventPayload::Setattr {
                ino,
                mode: change.mode,
                uid: change.uid,
                gid: change.gid,
                mtime_ns: change.mtime_ns.map(|_| mtime_ns),
            };
            Self::enqueue(tx, op_id, &payload, Some(&path), None, &[], seq)?;
            Ok(object)
        })
    }

    /// `fsync`: commit the WAL and return. Durability is local, not remote.
    pub fn fsync(&self) -> Result<(), DbError> {
        let db = self.lock_reader();
        db.checkpoint_wal()?;
        Ok(())
    }

    /// Drop chunks no longer referenced by the tree or the outbox.
    pub fn gc_chunks(&self) -> Result<u64, DbError> {
        self.write(|tx| {
            let removed = tx.conn().execute("DELETE FROM chunks WHERE refcount = 0", [])?;
            Ok(removed as u64)
        })
    }

    // -- helpers -----------------------------------------------------------

    fn current_local_seq(tx: &WriteTx<'_>) -> Result<i64, DbError> {
        let value: Option<i64> = tx
            .conn()
            .query_row(
                "SELECT value FROM meta WHERE key = 'local_seq'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value.unwrap_or(0))
    }

    fn path_in(tx: &WriteTx<'_>, ino: Ino) -> Result<String, DbError> {
        if ino == ROOT_INO {
            return Ok("/".to_owned());
        }
        let path: Option<String> = tx
            .conn()
            .query_row(
                "SELECT path FROM names WHERE ino = ?1 ORDER BY path LIMIT 1",
                [ino.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        path.ok_or(DbError::Errno(Errno::ENOENT))
    }

    pub(crate) fn name_in(tx: &WriteTx<'_>, parent: Ino, name: &str) -> Result<Option<Ino>, DbError> {
        let bytes: Option<Vec<u8>> = tx
            .conn()
            .query_row(
                "SELECT ino FROM names WHERE parent = ?1 AND name = ?2",
                params![parent.as_slice(), name],
                |row| row.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| {
                bytes
                    .try_into()
                    .map_err(|_| DbError::Corrupt("names.ino is not 16 bytes"))
            })
            .transpose()
    }

    fn remove_name(tx: &WriteTx<'_>, parent: Ino, name: &str) -> Result<Object, DbError> {
        let ino = Self::name_in(tx, parent, name)?.ok_or(DbError::Errno(Errno::ENOENT))?;
        let object = Self::object_in(tx, ino)?.ok_or(DbError::Errno(Errno::ENOENT))?;
        tx.delete_name(parent, name)?;
        if object.kind.is_dir() {
            bump_nlink(tx, parent, -1)?;
        }
        let mut updated = object.clone();
        updated.nlink = updated.nlink.saturating_sub(1);
        if updated.nlink == 0 {
            tx.set_object_chunks(ino, &[])?;
            updated.deleted = true;
            updated.nlink = 0;
        }
        updated.updated_seq = Self::current_local_seq(tx)?;
        tx.put_object(&updated)?;
        Ok(object)
    }

    pub(crate) fn rewrite_subtree_paths(
        tx: &WriteTx<'_>,
        old_prefix: &str,
        new_prefix: &str,
    ) -> Result<(), DbError> {
        let old_len = old_prefix.len() as i64;
        tx.conn().execute(
            "UPDATE names
                SET path = ?1 || substr(path, ?2 + 1)
              WHERE path = ?3
                 OR (substr(path, 1, ?2) = ?3 AND substr(path, ?2 + 1, 1) = '/')",
            params![new_prefix, old_len, old_prefix],
        )?;
        Ok(())
    }
}

/// Increment (`delta > 0`) or decrement a link count, clamping at zero.
pub(crate) fn bump_nlink(tx: &WriteTx<'_>, ino: Ino, delta: i32) -> Result<(), DbError> {
    let mut object = ClientDb::object_in(tx, ino)?.ok_or(DbError::Errno(Errno::ENOENT))?;
    let current = i64::from(object.nlink);
    let next = (current + i64::from(delta)).max(0);
    object.nlink = u32::try_from(next).map_err(|_| DbError::Corrupt("nlink out of range"))?;
    object.updated_seq = ClientDb::current_local_seq(tx)?;
    tx.put_object(&object)?;
    Ok(())
}

pub(crate) fn validate_name(name: &OsStr) -> Result<String, DbError> {
    let text = name.to_str().ok_or(DbError::Errno(Errno::EINVAL))?;
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > 255 {
        return Err(DbError::Errno(Errno::ENAMETOOLONG));
    }
    if text == "." || text == ".." || text.contains('/') || bytes.contains(&0) {
        return Err(DbError::Errno(Errno::EINVAL));
    }
    Ok(text.to_owned())
}

fn alloc_op_id() -> Ino {
    loop {
        let id = rand::random::<u128>().to_le_bytes();
        if id != [0u8; 16] {
            return id;
        }
    }
}

fn unsupported_kind(kind: ObjectKind) -> &'static str {
    match kind {
        ObjectKind::File => "file",
        ObjectKind::Dir => "dir",
        ObjectKind::Symlink => "symlink",
        _ => "special object is not representable in the event log",
    }
}
