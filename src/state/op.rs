//! Operations and the pure `plan` function.
//!
//! Every rule here is expressed as a precondition on [`State`] and a list of
//! [`Change`] rows. The function never mutates its arguments; the caller
//! either applies the rows in a SQLite transaction or, in tests, feeds them
//! back through [`State::commit`].

use super::{
    Attrs, Change, Chunk, Errno, Ino, Kind, LockKey, LockType, MAX_PATH_BYTES, Name, Object,
    ObjectPatch, Path, ROOT, Reject, State, Verdict, dir_root, empty_file_root, resolve_parent,
    resolve_path, symlink_root, validate_chunks,
};

/// One namespace operation.
///
/// `write` and `truncate` carry the *complete* chunk list after the operation.
/// The caller has already performed the read-modify-write of the affected
/// chunks and computed their hashes; the state machine validates the shape and
/// maintains `size`/`file_root`/`object_chunks`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// Create an empty regular file.
    CreateFile {
        /// Absolute path.
        path: Path,
        /// New identity.
        ino: Ino,
        /// Permission bits; masked to `0o7777`.
        mode: u32,
        /// Owner uid.
        uid: u32,
        /// Owner gid.
        gid: u32,
        /// Modification time.
        mtime_ns: u64,
    },
    /// Create an empty directory.
    CreateDir {
        /// Absolute path.
        path: Path,
        /// New identity.
        ino: Ino,
        /// Permission bits; masked to `0o7777`.
        mode: u32,
        /// Owner uid.
        uid: u32,
        /// Owner gid.
        gid: u32,
        /// Modification time.
        mtime_ns: u64,
    },
    /// Create a symbolic link.
    Symlink {
        /// Absolute path.
        path: Path,
        /// New identity.
        ino: Ino,
        /// Link contents; non-empty and at most [`MAX_PATH_BYTES`] bytes.
        target: Vec<u8>,
        /// Owner uid.
        uid: u32,
        /// Owner gid.
        gid: u32,
        /// Modification time.
        mtime_ns: u64,
    },
    /// Replace a file's content with a complete chunk list.
    Write {
        /// Absolute path.
        path: Path,
        /// Complete ordered chunk list after the write.
        chunks: Vec<Chunk>,
        /// Modification time.
        mtime_ns: u64,
    },
    /// Resize a file to a complete chunk list and a matching size.
    Truncate {
        /// Absolute path.
        path: Path,
        /// New size; must equal the sum of `chunks` lengths.
        size: u64,
        /// Complete ordered chunk list after the truncate.
        chunks: Vec<Chunk>,
        /// Modification time.
        mtime_ns: u64,
    },
    /// Change attributes, optionally with a size change.
    ///
    /// A size change carries the complete post-truncate chunk list, so one
    /// event applies the new length and the new metadata together.
    SetAttr {
        /// Absolute path.
        path: Path,
        /// Fields to change; `None` leaves a field unchanged.
        attrs: Attrs,
        /// New size, if this operation also truncates.
        size: Option<u64>,
        /// Complete ordered chunk list when `size` is `Some`.
        chunks: Vec<Chunk>,
    },
    /// Rename or move one directory entry.
    Rename {
        /// Source path.
        from: Path,
        /// Destination path.
        to: Path,
        /// Modification time applied to the source inode and both parents.
        mtime_ns: u64,
    },
    /// Remove one non-directory name.
    Unlink {
        /// Absolute path.
        path: Path,
        /// Modification time applied to the parent.
        mtime_ns: u64,
    },
    /// Remove one empty directory.
    Rmdir {
        /// Absolute path.
        path: Path,
        /// Modification time applied to the parent.
        mtime_ns: u64,
    },
    /// Add a hard link to an existing non-directory object.
    Link {
        /// Existing path.
        target: Path,
        /// New path.
        path: Path,
        /// Modification time applied to the new parent.
        mtime_ns: u64,
    },
    /// Acquire or replace an advisory lock range.
    Lock {
        /// Absolute path.
        path: Path,
        /// Holder.
        session: super::Session,
        /// Lock mode.
        typ: LockType,
        /// First byte, inclusive.
        start: u64,
        /// Last byte, inclusive.
        end: u64,
    },
    /// Release a session's locks overlapping a range.
    Unlock {
        /// Absolute path.
        path: Path,
        /// Holder.
        session: super::Session,
        /// First byte, inclusive.
        start: u64,
        /// Last byte, inclusive.
        end: u64,
    },
    /// Remove every lock held by a session.
    Leave {
        /// Holder.
        session: super::Session,
    },
}

impl Op {
    /// Stable operation name for logs and events.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::CreateFile { .. } => "create_file",
            Self::CreateDir { .. } => "create_dir",
            Self::Symlink { .. } => "symlink",
            Self::Write { .. } => "write",
            Self::Truncate { .. } => "truncate",
            Self::SetAttr { .. } => "setattr",
            Self::Rename { .. } => "rename",
            Self::Unlink { .. } => "unlink",
            Self::Rmdir { .. } => "rmdir",
            Self::Link { .. } => "link",
            Self::Lock { .. } => "lock",
            Self::Unlock { .. } => "unlock",
            Self::Leave { .. } => "leave",
        }
    }
}

/// Plan one operation against a state.
///
/// The function is pure: no I/O, no clock, no randomness. A rejected operation
/// produces no changes.
pub fn plan(op: &Op, state: &State) -> Verdict {
    match plan_inner(op, state) {
        Ok(changes) => Verdict::Apply(changes),
        Err(reject) => Verdict::Reject(reject),
    }
}

fn plan_inner(op: &Op, state: &State) -> Result<Vec<Change>, Reject> {
    match op {
        Op::CreateFile {
            path,
            ino,
            mode,
            uid,
            gid,
            mtime_ns,
        } => plan_create_file(state, path, *ino, *mode, *uid, *gid, *mtime_ns),
        Op::CreateDir {
            path,
            ino,
            mode,
            uid,
            gid,
            mtime_ns,
        } => plan_create_dir(state, path, *ino, *mode, *uid, *gid, *mtime_ns),
        Op::Symlink {
            path,
            ino,
            target,
            uid,
            gid,
            mtime_ns,
        } => plan_symlink(state, path, *ino, target, *uid, *gid, *mtime_ns),
        Op::Write {
            path,
            chunks,
            mtime_ns,
        } => plan_write(state, path, chunks, *mtime_ns),
        Op::Truncate {
            path,
            size,
            chunks,
            mtime_ns,
        } => plan_truncate(state, path, *size, chunks, *mtime_ns),
        Op::SetAttr {
            path,
            attrs,
            size,
            chunks,
        } => plan_setattr(state, path, attrs, *size, chunks),
        Op::Rename { from, to, mtime_ns } => plan_rename(state, from, to, *mtime_ns),
        Op::Unlink { path, mtime_ns } => plan_unlink(state, path, *mtime_ns),
        Op::Rmdir { path, mtime_ns } => plan_rmdir(state, path, *mtime_ns),
        Op::Link {
            target,
            path,
            mtime_ns,
        } => plan_link(state, target, path, *mtime_ns),
        Op::Lock {
            path,
            session,
            typ,
            start,
            end,
        } => plan_lock(state, path, *session, *typ, *start, *end),
        Op::Unlock {
            path,
            session,
            start,
            end,
        } => plan_unlock(state, path, *session, *start, *end),
        Op::Leave { session } => Ok(vec![Change::RemoveSessionLocks { session: *session }]),
    }
}

fn check_create(state: &State, path: &[u8], ino: Ino) -> Result<(Ino, Name), Reject> {
    if path == b"/" {
        return Err(Reject::new(Errno::EEXIST, "root already exists"));
    }
    let (parent, name) = resolve_parent(state, path)?;
    if state.lookup(parent, &name).is_some() {
        return Err(Reject::new(Errno::EEXIST, "name already exists"));
    }
    if ino == ROOT || state.object(ino).is_some() {
        return Err(Reject::new(Errno::EEXIST, "inode already exists"));
    }
    Ok((parent, name))
}

fn plan_create_file(
    state: &State,
    path: &[u8],
    ino: Ino,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime_ns: u64,
) -> Result<Vec<Change>, Reject> {
    let (parent, name) = check_create(state, path, ino)?;
    let object = Object {
        ino,
        kind: Kind::File,
        mode: mode & 0o7777,
        uid,
        gid,
        mtime_ns,
        size: 0,
        file_root: empty_file_root(),
        nlink: 1,
        target: None,
    };
    let parent_change = parent_update(state, parent, 0, mtime_ns)?;
    Ok(vec![
        Change::InsertObject(object),
        Change::InsertName { parent, name, ino },
        parent_change,
    ])
}

fn plan_create_dir(
    state: &State,
    path: &[u8],
    ino: Ino,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime_ns: u64,
) -> Result<Vec<Change>, Reject> {
    let (parent, name) = check_create(state, path, ino)?;
    let object = Object {
        ino,
        kind: Kind::Dir,
        mode: mode & 0o7777,
        uid,
        gid,
        mtime_ns,
        size: 0,
        file_root: dir_root(),
        nlink: 2,
        target: None,
    };
    let parent_change = parent_update(state, parent, 1, mtime_ns)?;
    Ok(vec![
        Change::InsertObject(object),
        Change::InsertName { parent, name, ino },
        parent_change,
    ])
}

fn plan_symlink(
    state: &State,
    path: &[u8],
    ino: Ino,
    target: &[u8],
    uid: u32,
    gid: u32,
    mtime_ns: u64,
) -> Result<Vec<Change>, Reject> {
    if target.is_empty() {
        return Err(Reject::new(Errno::EINVAL, "symlink target is empty"));
    }
    if target.len() > MAX_PATH_BYTES {
        return Err(Reject::new(
            Errno::ENAMETOOLONG,
            "symlink target is too long",
        ));
    }
    if target.contains(&0) {
        return Err(Reject::new(Errno::EINVAL, "symlink target contains NUL"));
    }
    let size = u64::try_from(target.len())
        .map_err(|_| Reject::new(Errno::EOVERFLOW, "symlink target length overflows u64"))?;
    let (parent, name) = check_create(state, path, ino)?;
    let object = Object {
        ino,
        kind: Kind::Symlink,
        mode: 0o777,
        uid,
        gid,
        mtime_ns,
        size,
        file_root: symlink_root(target),
        nlink: 1,
        target: Some(target.to_vec()),
    };
    let parent_change = parent_update(state, parent, 0, mtime_ns)?;
    Ok(vec![
        Change::InsertObject(object),
        Change::InsertName { parent, name, ino },
        parent_change,
    ])
}

fn plan_write(
    state: &State,
    path: &[u8],
    chunks: &[Chunk],
    mtime_ns: u64,
) -> Result<Vec<Change>, Reject> {
    let ino = resolve_path(state, path)?;
    let object = state
        .object(ino)
        .ok_or_else(|| Reject::new(Errno::ENOENT, "file does not exist"))?;
    match object.kind {
        Kind::File => {}
        Kind::Dir => return Err(Reject::new(Errno::EISDIR, "write targets a directory")),
        Kind::Symlink => {
            return Err(Reject::new(Errno::EINVAL, "write targets a symlink"));
        }
    }
    let (size, root) = validate_chunks(chunks)?;
    Ok(vec![
        Change::UpdateChunks {
            ino,
            chunks: chunks.to_vec(),
            size,
            file_root: root,
        },
        Change::SetAttrs {
            ino,
            attrs: Attrs {
                mtime_ns: Some(mtime_ns),
                ..Attrs::default()
            },
        },
    ])
}

fn plan_truncate(
    state: &State,
    path: &[u8],
    size: u64,
    chunks: &[Chunk],
    mtime_ns: u64,
) -> Result<Vec<Change>, Reject> {
    let ino = resolve_path(state, path)?;
    let object = state
        .object(ino)
        .ok_or_else(|| Reject::new(Errno::ENOENT, "file does not exist"))?;
    match object.kind {
        Kind::File => {}
        Kind::Dir => {
            return Err(Reject::new(Errno::EISDIR, "truncate targets a directory"));
        }
        Kind::Symlink => {
            return Err(Reject::new(Errno::EINVAL, "truncate targets a symlink"));
        }
    }
    let (computed, root) = validate_chunks(chunks)?;
    if computed != size {
        return Err(Reject::new(
            Errno::EINVAL,
            "truncate size does not match its chunks",
        ));
    }
    Ok(vec![
        Change::UpdateChunks {
            ino,
            chunks: chunks.to_vec(),
            size,
            file_root: root,
        },
        Change::SetAttrs {
            ino,
            attrs: Attrs {
                mtime_ns: Some(mtime_ns),
                ..Attrs::default()
            },
        },
    ])
}

fn plan_setattr(
    state: &State,
    path: &[u8],
    attrs: &Attrs,
    size: Option<u64>,
    chunks: &[Chunk],
) -> Result<Vec<Change>, Reject> {
    let ino = resolve_path(state, path)?;
    let object = state
        .object(ino)
        .ok_or_else(|| Reject::new(Errno::ENOENT, "object does not exist"))?;
    let mut changes = Vec::new();
    if let Some(size) = size {
        match object.kind {
            Kind::File => {}
            Kind::Dir => {
                return Err(Reject::new(
                    Errno::EISDIR,
                    "setattr size targets a directory",
                ));
            }
            Kind::Symlink => {
                return Err(Reject::new(Errno::EINVAL, "setattr size targets a symlink"));
            }
        }
        let (computed, root) = validate_chunks(chunks)?;
        if computed != size {
            return Err(Reject::new(
                Errno::EINVAL,
                "setattr size does not match its chunks",
            ));
        }
        changes.push(Change::UpdateChunks {
            ino,
            chunks: chunks.to_vec(),
            size,
            file_root: root,
        });
    }
    let attrs = Attrs {
        mode: attrs.mode.map(|mode| mode & 0o7777),
        uid: attrs.uid,
        gid: attrs.gid,
        mtime_ns: attrs.mtime_ns,
    };
    if attrs.mode.is_some()
        || attrs.uid.is_some()
        || attrs.gid.is_some()
        || attrs.mtime_ns.is_some()
    {
        changes.push(Change::SetAttrs { ino, attrs });
    }
    Ok(changes)
}

fn plan_unlink(state: &State, path: &[u8], mtime_ns: u64) -> Result<Vec<Change>, Reject> {
    if path == b"/" {
        return Err(Reject::new(Errno::EBUSY, "cannot unlink the root"));
    }
    let (parent, name) = resolve_parent(state, path)?;
    let ino = state
        .lookup(parent, &name)
        .ok_or_else(|| Reject::new(Errno::ENOENT, "name does not exist"))?;
    let object = state
        .object(ino)
        .ok_or_else(|| Reject::new(Errno::ENOENT, "object does not exist"))?;
    if object.kind == Kind::Dir {
        return Err(Reject::new(Errno::EISDIR, "unlink targets a directory"));
    }
    if object.nlink == 0 {
        return Err(Reject::new(Errno::EINVAL, "object has zero links"));
    }
    let parent_change = parent_update(state, parent, 0, mtime_ns)?;
    let mut changes = Vec::with_capacity(3);
    changes.push(Change::RemoveName { parent, name });
    if object.nlink == 1 {
        changes.push(Change::RemoveObject { ino });
    } else {
        changes.push(Change::UpdateObject {
            ino,
            patch: ObjectPatch {
                nlink: Some(object.nlink - 1),
                ..ObjectPatch::default()
            },
        });
    }
    changes.push(parent_change);
    Ok(changes)
}

fn plan_rmdir(state: &State, path: &[u8], mtime_ns: u64) -> Result<Vec<Change>, Reject> {
    if path == b"/" {
        return Err(Reject::new(Errno::EBUSY, "cannot remove the root"));
    }
    let (parent, name) = resolve_parent(state, path)?;
    let ino = state
        .lookup(parent, &name)
        .ok_or_else(|| Reject::new(Errno::ENOENT, "name does not exist"))?;
    let object = state
        .object(ino)
        .ok_or_else(|| Reject::new(Errno::ENOENT, "object does not exist"))?;
    if object.kind != Kind::Dir {
        return Err(Reject::new(Errno::ENOTDIR, "rmdir targets a non-directory"));
    }
    if state.children(ino).next().is_some() {
        return Err(Reject::new(Errno::ENOTEMPTY, "directory is not empty"));
    }
    if object.nlink != 2 {
        return Err(Reject::new(
            Errno::EINVAL,
            "empty directory has an inconsistent nlink",
        ));
    }
    let parent_change = parent_update(state, parent, -1, mtime_ns)?;
    Ok(vec![
        Change::RemoveName { parent, name },
        Change::RemoveObject { ino },
        parent_change,
    ])
}

fn plan_rename(
    state: &State,
    from: &[u8],
    to: &[u8],
    mtime_ns: u64,
) -> Result<Vec<Change>, Reject> {
    if from == b"/" || to == b"/" {
        return Err(Reject::new(Errno::EBUSY, "cannot rename the root"));
    }
    let (old_parent, old_name) = resolve_parent(state, from)?;
    let ino = state
        .lookup(old_parent, &old_name)
        .ok_or_else(|| Reject::new(Errno::ENOENT, "source does not exist"))?;
    let source = state
        .object(ino)
        .ok_or_else(|| Reject::new(Errno::ENOENT, "source object does not exist"))?;
    let (new_parent, new_name) = resolve_parent(state, to)?;
    if old_parent == new_parent && old_name == new_name {
        return Ok(Vec::new());
    }

    let existing = state.lookup(new_parent, &new_name);
    if existing == Some(ino) {
        // POSIX: two names for the same inode (hard links), or the same entry,
        // make rename a successful no-op. Both names stay.
        return Ok(Vec::new());
    }

    let source_is_dir = source.kind == Kind::Dir;
    let mut target_is_dir = false;
    let mut removed_target = None;
    let mut target_update = None;

    if let Some(target_ino) = existing {
        let target = state
            .object(target_ino)
            .ok_or_else(|| Reject::new(Errno::ENOENT, "target object does not exist"))?;
        target_is_dir = target.kind == Kind::Dir;
        if target_is_dir {
            if !source_is_dir {
                return Err(Reject::new(
                    Errno::EISDIR,
                    "a non-directory cannot replace a directory",
                ));
            }
            if state.children(target_ino).next().is_some() {
                return Err(Reject::new(
                    Errno::ENOTEMPTY,
                    "target directory is not empty",
                ));
            }
            if target.nlink != 2 {
                return Err(Reject::new(
                    Errno::EINVAL,
                    "empty target directory has an inconsistent nlink",
                ));
            }
            removed_target = Some(target_ino);
        } else {
            if source_is_dir {
                return Err(Reject::new(
                    Errno::ENOTDIR,
                    "a directory cannot replace a non-directory",
                ));
            }
            if target.nlink == 0 {
                return Err(Reject::new(Errno::EINVAL, "target has zero links"));
            }
            if target.nlink == 1 {
                removed_target = Some(target_ino);
            } else {
                target_update = Some(Change::UpdateObject {
                    ino: target_ino,
                    patch: ObjectPatch {
                        nlink: Some(target.nlink - 1),
                        ..ObjectPatch::default()
                    },
                });
            }
        }
    }

    if source_is_dir && is_descendant(state, new_parent, ino) {
        return Err(Reject::new(
            Errno::EINVAL,
            "a directory cannot move into its own subtree",
        ));
    }

    let old_parent_object = state
        .object(old_parent)
        .ok_or_else(|| Reject::new(Errno::ENOENT, "old parent does not exist"))?;
    let new_parent_object = state
        .object(new_parent)
        .ok_or_else(|| Reject::new(Errno::ENOENT, "new parent does not exist"))?;
    let (old_nlink, new_nlink) = if old_parent == new_parent {
        let next = checked_dir_nlink(new_parent_object.nlink, -i32::from(target_is_dir))?;
        (next, next)
    } else {
        let old_next = checked_dir_nlink(old_parent_object.nlink, -i32::from(source_is_dir))?;
        let new_next = checked_dir_nlink(
            new_parent_object.nlink,
            i32::from(source_is_dir) - i32::from(target_is_dir),
        )?;
        (old_next, new_next)
    };

    let mut changes = Vec::with_capacity(8);
    changes.push(Change::RemoveName {
        parent: old_parent,
        name: old_name,
    });
    if existing.is_some() {
        changes.push(Change::RemoveName {
            parent: new_parent,
            name: new_name.clone(),
        });
    }
    changes.push(Change::InsertName {
        parent: new_parent,
        name: new_name,
        ino,
    });
    changes.push(Change::UpdateObject {
        ino,
        patch: ObjectPatch {
            mtime_ns: Some(mtime_ns),
            ..ObjectPatch::default()
        },
    });
    if old_parent == new_parent {
        changes.push(Change::UpdateObject {
            ino: old_parent,
            patch: ObjectPatch {
                nlink: Some(new_nlink),
                mtime_ns: Some(mtime_ns),
                ..ObjectPatch::default()
            },
        });
    } else {
        changes.push(Change::UpdateObject {
            ino: old_parent,
            patch: ObjectPatch {
                nlink: Some(old_nlink),
                mtime_ns: Some(mtime_ns),
                ..ObjectPatch::default()
            },
        });
        changes.push(Change::UpdateObject {
            ino: new_parent,
            patch: ObjectPatch {
                nlink: Some(new_nlink),
                mtime_ns: Some(mtime_ns),
                ..ObjectPatch::default()
            },
        });
    }
    if let Some(target) = removed_target {
        changes.push(Change::RemoveObject { ino: target });
    }
    if let Some(change) = target_update {
        changes.push(change);
    }
    Ok(changes)
}

fn plan_link(
    state: &State,
    target: &[u8],
    path: &[u8],
    mtime_ns: u64,
) -> Result<Vec<Change>, Reject> {
    if path == b"/" {
        return Err(Reject::new(Errno::EEXIST, "root already exists"));
    }
    let target_ino = resolve_path(state, target)?;
    let target_object = state
        .object(target_ino)
        .ok_or_else(|| Reject::new(Errno::ENOENT, "link target does not exist"))?;
    if target_object.kind == Kind::Dir {
        return Err(Reject::new(Errno::EPERM, "cannot hard-link a directory"));
    }
    if target_object.nlink == 0 {
        return Err(Reject::new(Errno::EINVAL, "link target has zero links"));
    }
    let next = target_object
        .nlink
        .checked_add(1)
        .ok_or_else(|| Reject::new(Errno::EOVERFLOW, "link count overflow"))?;
    let (parent, name) = resolve_parent(state, path)?;
    if state.lookup(parent, &name).is_some() {
        return Err(Reject::new(Errno::EEXIST, "name already exists"));
    }
    let parent_change = parent_update(state, parent, 0, mtime_ns)?;
    Ok(vec![
        Change::InsertName {
            parent,
            name,
            ino: target_ino,
        },
        Change::UpdateObject {
            ino: target_ino,
            patch: ObjectPatch {
                nlink: Some(next),
                ..ObjectPatch::default()
            },
        },
        parent_change,
    ])
}

fn plan_lock(
    state: &State,
    path: &[u8],
    session: super::Session,
    typ: LockType,
    start: u64,
    end: u64,
) -> Result<Vec<Change>, Reject> {
    let ino = resolve_path(state, path)?;
    if start > end {
        return Err(Reject::new(Errno::EINVAL, "lock range is inverted"));
    }
    let requested = LockKey { ino, start, end };
    for (key, lock) in state.locks() {
        if lock.session == session {
            continue;
        }
        if key.overlaps(requested) && (lock.typ == LockType::Write || typ == LockType::Write) {
            return Err(Reject::new(
                Errno::EAGAIN,
                "lock conflicts with another session",
            ));
        }
    }
    let remainders = split_locks(state, session, ino, start, end);
    let mut changes = Vec::with_capacity(2 + remainders.len());
    changes.push(Change::RemoveLocks {
        session,
        ino,
        start,
        end,
    });
    for (key, typ) in remainders {
        changes.push(Change::InsertLock { key, session, typ });
    }
    changes.push(Change::InsertLock {
        key: requested,
        session,
        typ,
    });
    Ok(changes)
}

fn plan_unlock(
    state: &State,
    path: &[u8],
    session: super::Session,
    start: u64,
    end: u64,
) -> Result<Vec<Change>, Reject> {
    let ino = resolve_path(state, path)?;
    if start > end {
        return Err(Reject::new(Errno::EINVAL, "lock range is inverted"));
    }
    let remainders = split_locks(state, session, ino, start, end);
    let mut changes = Vec::with_capacity(1 + remainders.len());
    changes.push(Change::RemoveLocks {
        session,
        ino,
        start,
        end,
    });
    for (key, typ) in remainders {
        changes.push(Change::InsertLock { key, session, typ });
    }
    Ok(changes)
}

/// The parts of a session's locks that stick out past `[start, end]`.
///
/// `RemoveLocks` deletes every overlapping row, so a partial lock or unlock
/// re-inserts the left and right remainders. This is the POSIX `fcntl`
/// trim/split rule, expressed with the two change kinds the schema has.
fn split_locks(
    state: &State,
    session: super::Session,
    ino: Ino,
    start: u64,
    end: u64,
) -> Vec<(LockKey, LockType)> {
    let mut remainders = Vec::new();
    for (key, lock) in state.locks() {
        if lock.session != session || key.ino != ino || key.start > end || start > key.end {
            continue;
        }
        if key.start < start {
            remainders.push((
                LockKey {
                    ino,
                    start: key.start,
                    end: start - 1,
                },
                lock.typ,
            ));
        }
        if key.end > end {
            remainders.push((
                LockKey {
                    ino,
                    start: end + 1,
                    end: key.end,
                },
                lock.typ,
            ));
        }
    }
    remainders
}

fn parent_update(state: &State, parent: Ino, delta: i32, mtime_ns: u64) -> Result<Change, Reject> {
    let object = state
        .object(parent)
        .ok_or_else(|| Reject::new(Errno::ENOENT, "parent does not exist"))?;
    if object.kind != Kind::Dir {
        return Err(Reject::new(Errno::ENOTDIR, "parent is not a directory"));
    }
    let nlink = if delta == 0 {
        None
    } else {
        Some(checked_dir_nlink(object.nlink, delta)?)
    };
    Ok(Change::UpdateObject {
        ino: parent,
        patch: ObjectPatch {
            nlink,
            mtime_ns: Some(mtime_ns),
            ..ObjectPatch::default()
        },
    })
}

fn checked_dir_nlink(nlink: u32, delta: i32) -> Result<u32, Reject> {
    let next = i64::from(nlink) + i64::from(delta);
    if next < 2 {
        return Err(Reject::new(
            Errno::EINVAL,
            "directory nlink would drop below two",
        ));
    }
    if next > i64::from(u32::MAX) {
        return Err(Reject::new(Errno::EOVERFLOW, "directory nlink overflow"));
    }
    Ok(next as u32)
}

fn is_descendant(state: &State, mut node: Ino, ancestor: Ino) -> bool {
    for _ in 0..=state.len() {
        if node == ancestor {
            return true;
        }
        if node == ROOT {
            return false;
        }
        match state.parent_of(node) {
            Some(parent) => node = parent,
            None => return false,
        }
    }
    // A cycle: reject the move rather than loop.
    true
}
