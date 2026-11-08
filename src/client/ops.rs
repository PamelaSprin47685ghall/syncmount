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
use super::writeback::InodeBuffer;
use crate::store::Errno;
use crate::store::sqlite::{self, ChunkRef, EventPayload, Object, ObjectKind, ROOT_INO, WriteTx};

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
            let parent_object =
                Self::object_in(tx, parent)?.ok_or(DbError::Errno(Errno::ENOENT))?;
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
            // The server records the create's timestamp on the parent as
            // well. Keep the optimistic local tree identical so an own echo
            // can stay ack-only.
            touch_object(tx, parent, mtime_ns, seq)?;
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
        let mtime_ns = now_ns();
        self.write(|tx| {
            let object = Self::object_in(tx, ino)?.ok_or(DbError::Errno(Errno::ENOENT))?;
            if object.deleted {
                return Err(DbError::Errno(Errno::ENOENT));
            }
            if object.kind.is_dir() {
                return Err(DbError::Errno(Errno::EPERM));
            }
            let parent = Self::object_in(tx, newparent)?.ok_or(DbError::Errno(Errno::ENOENT))?;
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
            touch_object(tx, newparent, mtime_ns, seq)?;
            Self::next_fuse_ino(tx, ino)?;
            let mut linked = object;
            linked.nlink = linked.nlink.saturating_add(1);
            Self::enqueue(
                tx,
                op_id,
                &EventPayload::Link {
                    ino,
                    mtime_ns: Some(mtime_ns),
                },
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
        let mtime_ns = now_ns();
        self.flush_entry(parent, name)?;
        self.write(|tx| {
            let object = Self::remove_name(tx, parent, &name_text)?;
            if object.kind.is_dir() {
                return Err(DbError::Errno(Errno::EISDIR));
            }
            let seq = Self::next_local_seq(tx)?;
            let op_id = alloc_op_id();
            let path = join_path(&Self::path_in(tx, parent)?, &name_text);
            touch_object(tx, parent, mtime_ns, seq)?;
            Self::enqueue(
                tx,
                op_id,
                &EventPayload::Unlink {
                    ino: object.ino,
                    mtime_ns: Some(mtime_ns),
                },
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
        let mtime_ns = now_ns();
        self.write(|tx| {
            let entry =
                Self::name_in(tx, parent, &name_text)?.ok_or(DbError::Errno(Errno::ENOENT))?;
            let object = Self::object_in(tx, entry)?.ok_or(DbError::Errno(Errno::ENOENT))?;
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
            touch_object(tx, parent, mtime_ns, seq)?;
            Self::enqueue(
                tx,
                op_id,
                &EventPayload::Rmdir {
                    ino: object.ino,
                    mtime_ns: Some(mtime_ns),
                },
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
        let mtime_ns = now_ns();
        self.flush_entry(old_parent, old_name)?;
        self.flush_entry(new_parent, new_name)?;
        self.write(|tx| {
            let entry =
                Self::name_in(tx, old_parent, &old_text)?.ok_or(DbError::Errno(Errno::ENOENT))?;
            let object = Self::object_in(tx, entry)?.ok_or(DbError::Errno(Errno::ENOENT))?;
            let new_parent_object =
                Self::object_in(tx, new_parent)?.ok_or(DbError::Errno(Errno::ENOENT))?;
            if !new_parent_object.kind.is_dir() || new_parent_object.deleted {
                return Err(DbError::Errno(Errno::ENOTDIR));
            }
            // The source path is the directory entry being renamed, not the
            // object's smallest path: a hard-linked inode has several names.
            let old_parent_path = Self::path_in(tx, old_parent)?;
            let old_path = join_path(&old_parent_path, &old_text);
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
                if target_ino == object.ino {
                    // POSIX: renaming one hard link of a file onto another
                    // link of the same file succeeds and does nothing. Both
                    // names stay and no event is needed.
                    return Ok(());
                }
                let target_object =
                    Self::object_in(tx, target_ino)?.ok_or(DbError::Errno(Errno::ENOENT))?;
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
            touch_object(tx, object.ino, mtime_ns, seq)?;
            touch_object(tx, old_parent, mtime_ns, seq)?;
            if old_parent != new_parent {
                touch_object(tx, new_parent, mtime_ns, seq)?;
            }
            Self::next_fuse_ino(tx, object.ino)?;
            Self::enqueue(
                tx,
                op_id,
                &EventPayload::Rename {
                    ino: object.ino,
                    mtime_ns: Some(mtime_ns),
                },
                Some(&old_path),
                Some(&new_path),
                &[],
                seq,
            )?;
            Ok(())
        })
    }

    /// Buffer a write and return. The bytes are visible to local reads at
    /// once; SQLite receives them on the next flush or background commit.
    pub fn write_at(&self, ino: Ino, off: u64, data: &[u8]) -> Result<usize, DbError> {
        if data.is_empty() {
            return Ok(0);
        }
        let object = self.getattr(ino)?;
        if object.kind.is_dir() {
            return Err(DbError::Errno(Errno::EISDIR));
        }
        if !object.kind.is_file() {
            return Err(DbError::Errno(Errno::EINVAL));
        }
        off.checked_add(data.len() as u64)
            .ok_or(DbError::Errno(Errno::EOVERFLOW))?;

        if self.writeback.insert(ino, off, data) {
            self.writeback.note_cap_hit();
            tracing::warn!(
                event = "writeback_cap",
                buffered = self.writeback.stats().buffered_bytes,
                cap = self.writeback.config().max_bytes,
                "write-back buffer reached its soft cap; committing synchronously"
            );
            if let Err(error) = self.flush_all() {
                tracing::warn!(
                    event = "writeback_cap_flush",
                    error = %error,
                    "synchronous cap commit failed; the bytes stay buffered"
                );
            }
        }
        Ok(data.len())
    }

    /// Commit one buffered inode into SQLite and the outbox.
    ///
    /// All ranges held for the inode become one `Write` event whose offset
    /// spans them and whose chunk list carries every touched chunk. This is
    /// the same chunk-granular overwrite the synchronous path used, with a
    /// window of at most one flush interval.
    /// Commit a whole write-back tick in one transaction.
    ///
    /// Every dirty inode is part of the same `BEGIN IMMEDIATE` and the same
    /// commit. A failure rolls the whole batch back; no inode is committed
    /// alone. There is no inode or byte cap here: the buffer's memory bound is
    /// the only limit.
    pub(crate) fn commit_buffered_batch(
        &self,
        batch: &[(Ino, &InodeBuffer)],
    ) -> Result<(), DbError> {
        if batch.is_empty() {
            return Ok(());
        }
        let mut db = self.lock_writer();
        let tx = db.write()?;
        for (ino, buffer) in batch {
            Self::commit_buffered_in_tx(&tx, *ino, buffer)?;
        }
        tx.commit()?;
        Ok(())
    }

    fn commit_buffered_in_tx(
        tx: &WriteTx<'_>,
        ino: Ino,
        buffer: &InodeBuffer,
    ) -> Result<(), DbError> {
        if buffer.is_empty() {
            return Ok(());
        }
        let Some(mut object) = Self::object_in(tx, ino)? else {
            return Err(DbError::Errno(Errno::ENOENT));
        };
        if object.deleted {
            return Err(DbError::Errno(Errno::ENOENT));
        }
        if !object.kind.is_file() {
            return Err(DbError::Errno(Errno::EINVAL));
        }

        let old_refs = Self::object_chunks_in(tx, ino)?;
        let mut by_no: BTreeMap<u32, ChunkRef> = old_refs
            .into_iter()
            .map(|chunk| (chunk.chunk_no, chunk))
            .collect();
        let mut written: BTreeMap<u32, ChunkRef> = BTreeMap::new();
        let mut min_off = u64::MAX;
        let mut max_end = 0u64;
        for (off, data) in buffer.segments() {
            if data.is_empty() {
                continue;
            }
            let end = off
                .checked_add(data.len() as u64)
                .ok_or(DbError::Errno(Errno::EOVERFLOW))?;
            Self::overlay_in(tx, &mut object.size, &mut by_no, off, data, &mut written)?;
            min_off = min_off.min(off);
            max_end = max_end.max(end);
        }
        if min_off == u64::MAX {
            return Ok(());
        }

        let size = object.size;
        // A short chunk that was final before this commit is no longer final
        // once a later range extends the file. Pad it so `assemble_chunks`
        // does not replace it with a zero chunk.
        let chunk_numbers: Vec<u32> = by_no.keys().copied().collect();
        for chunk_no in chunk_numbers {
            let chunk_start = u64::from(chunk_no) * CHUNK;
            if chunk_start >= size {
                by_no.remove(&chunk_no);
                continue;
            }
            let expected = ((size - chunk_start).min(CHUNK)) as u32;
            let Some(reference) = by_no.get(&chunk_no).cloned() else {
                continue;
            };
            if reference.len == expected {
                continue;
            }
            let mut bytes = Self::chunk_data_in(tx, reference.hash)?
                .ok_or(DbError::MissingChunk(reference.hash))?;
            bytes.resize(expected as usize, 0);
            let reference = Self::put_chunk_ref(tx, chunk_no, &bytes)?;
            by_no.insert(chunk_no, reference.clone());
            written.insert(chunk_no, reference);
            // The event range must cover every chunk it carries.
            min_off = min_off.min(chunk_start);
            max_end = max_end.max(chunk_start + u64::from(expected));
        }

        // The event's chunk list is also the uplink's byte stream: `send_wire`
        // walks it in chunk order. Every chunk between the first and the last
        // touched chunk must be present, or the holes vanish and the later
        // chunks land at the wrong offsets on the server. Fill each untouched
        // hole with its zero chunk; the local tree already got the same zero
        // chunk from `assemble_chunks`.
        let first_chunk = u32::try_from(min_off / CHUNK)
            .map_err(|_| DbError::Corrupt("chunk number out of range"))?;
        let last_chunk = u32::try_from((max_end - 1) / CHUNK)
            .map_err(|_| DbError::Corrupt("chunk number out of range"))?;
        for chunk_no in first_chunk..=last_chunk {
            if written.contains_key(&chunk_no) {
                continue;
            }
            let chunk_start = u64::from(chunk_no) * CHUNK;
            let len = ((size - chunk_start).min(CHUNK)) as u32;
            let reference = Self::zero_chunk(tx, chunk_no, len)?;
            by_no.insert(chunk_no, reference.clone());
            written.insert(chunk_no, reference);
        }

        let refs = Self::assemble_chunks(tx, size, &by_no)?;
        let file_root = sqlite::file_root(ObjectKind::File, None, &refs);
        let mtime_ns = now_ns();
        object.size = size;
        object.block_count =
            u32::try_from(refs.len()).map_err(|_| DbError::Corrupt("too many chunks"))?;
        object.file_root = file_root;
        object.mtime_ns = mtime_ns;
        object.updated_seq = Self::current_local_seq(tx)?;
        tx.put_object(&object)?;
        tx.set_object_chunks(ino, &refs)?;

        let chunks: Vec<ChunkRef> = written.into_values().collect();
        let payload = EventPayload::Write {
            ino,
            offset: min_off,
            len: max_end - min_off,
            size,
            file_root,
            mtime_ns,
            chunks: chunks.clone(),
        };
        let seq = Self::next_local_seq(tx)?;
        let op_id = alloc_op_id();
        let path = Self::path_in(tx, ino)?;
        Self::enqueue(tx, op_id, &payload, Some(&path), None, &chunks, seq)?;
        Ok(())
    }

    /// Apply one byte range to the chunk map inside a write transaction.
    fn overlay_in(
        tx: &WriteTx<'_>,
        size: &mut u64,
        by_no: &mut BTreeMap<u32, ChunkRef>,
        off: u64,
        data: &[u8],
        written: &mut BTreeMap<u32, ChunkRef>,
    ) -> Result<(), DbError> {
        let end = off
            .checked_add(data.len() as u64)
            .ok_or(DbError::Errno(Errno::EOVERFLOW))?;
        let new_size = (*size).max(end);
        let first = off / CHUNK;
        let last = (end - 1) / CHUNK;
        for chunk_no in first..=last {
            let chunk_no_u32 = u32::try_from(chunk_no)
                .map_err(|_| DbError::Corrupt("chunk number out of range"))?;
            let chunk_start = chunk_no * CHUNK;
            let final_len = ((new_size - chunk_start).min(CHUNK)) as u32;
            let write_start = off.max(chunk_start);
            let write_end = end.min(chunk_start + CHUNK);
            let covers_chunk =
                write_start == chunk_start && write_end == chunk_start + u64::from(final_len);
            let mut bytes = if covers_chunk {
                Vec::new()
            } else {
                match by_no.get(&chunk_no_u32) {
                    Some(existing) => Self::chunk_data_in(tx, existing.hash)?
                        .ok_or(DbError::MissingChunk(existing.hash))?,
                    None => Vec::new(),
                }
            };
            bytes.resize(final_len as usize, 0);
            if write_start < write_end {
                let from = (write_start - chunk_start) as usize;
                let to = (write_end - chunk_start) as usize;
                let src = (write_start - off) as usize;
                bytes[from..to].copy_from_slice(&data[src..src + (to - from)]);
            }
            let reference = Self::put_chunk_ref(tx, chunk_no_u32, &bytes)?;
            by_no.insert(chunk_no_u32, reference.clone());
            written.insert(chunk_no_u32, reference);
        }
        *size = new_size;
        Ok(())
    }

    /// Apply a size change inside `tx` and return the touched chunks.
    ///
    /// The caller owns the transaction and decides which event records the
    /// change. `truncate` records a `truncate` event; a size-changing
    /// `setattr` records one `setattr` event that carries size and metadata
    /// together. Both keep the object row, the chunk list and the outbox row
    /// in one commit.
    fn resize_in(
        tx: &WriteTx<'_>,
        ino: Ino,
        size: u64,
    ) -> Result<(Object, Vec<ChunkRef>), DbError> {
        let mut object = Self::object_in(tx, ino)?.ok_or(DbError::Errno(Errno::ENOENT))?;
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
            return Ok((object, Vec::new()));
        }
        let old_refs = Self::object_chunks_in(tx, ino)?;
        let mut by_no: BTreeMap<u32, ChunkRef> = old_refs
            .into_iter()
            .map(|chunk| (chunk.chunk_no, chunk))
            .collect();
        let old_size = object.size;
        let mtime_ns = now_ns();
        let mut touched = Vec::new();
        if size > old_size {
            // Extend the boundary chunk with zeroes when the old size was not
            // chunk-aligned; `assemble_chunks` fills whole missing chunks.
            let chunk_no = old_size / CHUNK;
            if let Some(existing) = by_no.get(&(chunk_no as u32)).cloned() {
                let mut buffer = Self::chunk_data_in(tx, existing.hash)?
                    .ok_or(DbError::MissingChunk(existing.hash))?;
                let final_len = ((size - chunk_no * CHUNK).min(CHUNK)) as usize;
                if buffer.len() < final_len {
                    buffer.resize(final_len, 0);
                    let reference = Self::put_chunk_ref(tx, chunk_no as u32, &buffer)?;
                    by_no.insert(chunk_no as u32, reference.clone());
                    touched.push(reference);
                }
            }
        } else {
            // Shrink: the boundary chunk keeps its prefix only.
            let chunk_no = size / CHUNK;
            if size % CHUNK != 0 {
                if let Some(existing) = by_no.get(&(chunk_no as u32)).cloned() {
                    let mut buffer = Self::chunk_data_in(tx, existing.hash)?
                        .ok_or(DbError::MissingChunk(existing.hash))?;
                    buffer.truncate((size - chunk_no * CHUNK) as usize);
                    let reference = Self::put_chunk_ref(tx, chunk_no as u32, &buffer)?;
                    by_no.insert(chunk_no as u32, reference.clone());
                    touched.push(reference);
                }
            }
            let keep = size.div_ceil(CHUNK) as u32;
            by_no.retain(|chunk_no, _| *chunk_no < keep);
        }
        let refs = Self::assemble_chunks(tx, size, &by_no)?;
        let file_root = sqlite::file_root(ObjectKind::File, None, &refs);
        object.size = size;
        object.block_count =
            u32::try_from(refs.len()).map_err(|_| DbError::Corrupt("too many chunks"))?;
        object.file_root = file_root;
        object.mtime_ns = mtime_ns;
        object.updated_seq = Self::current_local_seq(tx)?;
        tx.put_object(&object)?;
        tx.set_object_chunks(ino, &refs)?;
        Ok((object, touched))
    }

    /// Apply a size change and enqueue its `truncate` event inside `tx`.
    fn truncate_in(tx: &WriteTx<'_>, ino: Ino, size: u64) -> Result<Object, DbError> {
        let current = Self::object_in(tx, ino)?.ok_or(DbError::Errno(Errno::ENOENT))?;
        if current.deleted {
            return Err(DbError::Errno(Errno::ENOENT));
        }
        if current.kind.is_dir() {
            return Err(DbError::Errno(Errno::EISDIR));
        }
        if !current.kind.is_file() {
            return Err(DbError::Errno(Errno::EINVAL));
        }
        if current.size == size {
            return Ok(current);
        }
        let (object, touched) = Self::resize_in(tx, ino, size)?;
        let file_root = object.file_root;
        let mtime_ns = object.mtime_ns;
        let payload = EventPayload::Truncate {
            ino,
            size,
            file_root,
            mtime_ns,
        };
        let seq = Self::next_local_seq(tx)?;
        let op_id = alloc_op_id();
        let path = Self::path_in(tx, ino)?;
        Self::enqueue(tx, op_id, &payload, Some(&path), None, &touched, seq)?;
        Ok(object)
    }

    /// Truncate a regular file in one transaction.
    pub fn truncate(&self, ino: Ino, size: u64) -> Result<(), DbError> {
        self.flush_ino(ino)?;
        self.write(|tx| {
            Self::truncate_in(tx, ino, size)?;
            Ok(())
        })
    }

    /// Apply attribute changes, including a size change, in one transaction.
    ///
    /// A size change and the metadata change become one `setattr` event, so
    /// the server commits both in one transaction and a crash cannot leave
    /// the new size with the old mode.
    pub fn setattr(&self, ino: Ino, change: AttrChange) -> Result<Object, DbError> {
        if change.size.is_some() {
            self.flush_ino(ino)?;
        }
        let mtime_ns = change.mtime_ns.unwrap_or_else(now_ns);
        self.write(|tx| {
            let mut object = Self::object_in(tx, ino)?.ok_or(DbError::Errno(Errno::ENOENT))?;
            if object.deleted {
                return Err(DbError::Errno(Errno::ENOENT));
            }
            let mut touched = Vec::new();
            let mut size_changed = false;
            if let Some(size) = change.size {
                if size != object.size {
                    let (resized, chunks) = Self::resize_in(tx, ino, size)?;
                    object = resized;
                    touched = chunks;
                    size_changed = true;
                }
            }
            let mut changed = size_changed;
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
                mtime_ns: if size_changed {
                    Some(object.mtime_ns)
                } else {
                    change.mtime_ns.map(|_| mtime_ns)
                },
                size: if size_changed { Some(object.size) } else { None },
            };
            Self::enqueue(tx, op_id, &payload, Some(&path), None, &touched, seq)?;
            Ok(object)
        })
    }

    /// `fsync`: commit buffered writes, sync the WAL and return.
    ///
    /// Durability is local, not remote. The checkpoint moved to the
    /// background PASSIVE thread: copying WAL pages into the main database is
    /// housekeeping, and doing it here made every `fsync` wait for a
    /// TRUNCATE checkpoint that a concurrent reader can block.
    pub fn fsync(&self) -> Result<(), DbError> {
        self.flush_all()?;
        self.sync_wal()
    }

    /// Drop chunks no longer referenced by the tree or the outbox.
    pub fn gc_chunks(&self) -> Result<u64, DbError> {
        self.write(|tx| {
            let removed = tx
                .conn()
                .execute("DELETE FROM chunks WHERE refcount = 0", [])?;
            Ok(removed as u64)
        })
    }

    // -- helpers -----------------------------------------------------------

    /// Commit the buffered data of one directory entry, if the entry exists.
    ///
    /// Namespace mutations call this before changing the tree so a buffered
    /// write keeps its outbox position ahead of the rename/unlink event.
    fn flush_entry(&self, parent: Ino, name: &OsStr) -> Result<(), DbError> {
        match self.lookup(parent, name) {
            Ok(object) => self.flush_ino(object.ino),
            Err(DbError::Errno(Errno::ENOENT)) => Ok(()),
            Err(error) => Err(error),
        }
    }

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

    pub(crate) fn name_in(
        tx: &WriteTx<'_>,
        parent: Ino,
        name: &str,
    ) -> Result<Option<Ino>, DbError> {
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
        if updated.kind.is_dir() {
            // A directory has one name and `nlink` counts its own `.` link.
            // Removing that name removes the directory itself; decrementing
            // `nlink` would leave a live, nameless directory behind.
            tx.set_object_chunks(ino, &[])?;
            updated.deleted = true;
            updated.nlink = 0;
        } else {
            updated.nlink = updated.nlink.saturating_sub(1);
            if updated.nlink == 0 {
                tx.set_object_chunks(ino, &[])?;
                updated.deleted = true;
                updated.nlink = 0;
            }
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

/// Set one object's modification time and replay watermark.
pub(crate) fn touch_object(
    tx: &WriteTx<'_>,
    ino: Ino,
    mtime_ns: i64,
    seq: i64,
) -> Result<(), DbError> {
    let mut object = ClientDb::object_in(tx, ino)?.ok_or(DbError::Errno(Errno::ENOENT))?;
    object.mtime_ns = mtime_ns;
    object.updated_seq = seq;
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
