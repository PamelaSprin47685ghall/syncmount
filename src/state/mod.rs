//! Shared, pure namespace state machine for server and client.
//!
//! This module is deliberately independent of SQLite, the network, the store
//! layer and the FUSE layer. It defines the objects, names, chunks and locks
//! that both ends keep in their core tables, and it turns one [`Op`] into a
//! list of row-level [`Change`] values inside a SQLite transaction. The same
//! function is the test oracle for both ends.
//!
//! # Shape
//!
//! ```text
//! plan(op, state) -> Verdict::Apply(changes) | Verdict::Reject(reason)
//! state.commit(changes)      // test/oracle path
//! state.apply(op)            // plan + commit, test/oracle path
//! ```
//!
//! `plan` never touches the clock, the filesystem or a database. Every value
//! it needs is in the [`Op`] or in [`State`].
//!
//! # Invariants
//!
//! [`State::check_invariants`] is the executable form of the schema rules:
//!
//! - the root is inode 0, a directory with `nlink = 2 + direct subdirectories`;
//! - every non-root object has at least one name;
//! - a directory has exactly one name and `nlink = 2 + direct subdirectories`;
//! - a file or symlink has `nlink = number of names`;
//! - a file's chunks are non-empty, at most 64 KiB each, full except the last,
//!   and `size = sum(len)`; `file_root` is the 64 KiB Merkle root;
//! - a directory has no chunks, `size = 0`, and `file_root = dir_root()`;
//! - a symlink has no chunks, a non-empty target, `size = target.len()`, and
//!   `file_root = symlink_root(target)`;
//! - every name's parent is a directory, and no directory cycle exists;
//! - every lock names an existing inode and a valid range.
//!
//! # Not in this module
//!
//! Chunk bytes, their BLAKE3 verification and the `chunks` table are the
//! caller's job. A [`Chunk`] here is the reference `(hash, len)` that the
//! caller has already materialized. The state machine only checks the shape
//! of the reference list.
//!
//! # Derived columns
//!
//! The design's `names` table also carries a `path` cache. This module keeps
//! only `(parent, name) -> ino`; a SQLite writer that keeps `names.path` must
//! rewrite the affected subtree after a rename (or drop the column and derive
//! the path with a recursive query). The [`Change`] list deliberately carries
//! no path payload, because the path is not part of the namespace state.
//!
//! For the same reason, [`Change::UpdateChunks`] is the single source of
//! truth for a file's `size` and `file_root`. [`ObjectPatch`] still has those
//! fields for snapshot repair, but [`plan`] never sets them; it updates the
//! object row through `UpdateChunks`.
//!
//! # Deletion
//!
//! [`Change::RemoveObject`] is a hard delete. The design's `objects.deleted`
//! tombstone is not part of [`State`]; a SQLite writer that keeps the column
//! must translate `RemoveObject` into `deleted = 1, nlink = 0` and must not
//! reuse the inode. `plan` only checks the live objects in [`State`], so
//! inode allocation belongs to the caller.
//!
//! # Locks
//!
//! Lock ranges are inclusive `[start, end]`; `end == u64::MAX` means "to end
//! of file". The design's `locks` table stores `(start, len)`, so a writer
//! converts `len = end - start + 1` (or `0` for the EOF case). A partial lock
//! or unlock removes the overlapping rows and re-inserts the left and right
//! remainders, which is the POSIX `fcntl` trim rule.

use std::collections::BTreeMap;
use std::fmt;

pub mod op;

pub use op::{Op, plan};

/// A 128-bit inode identity. Zero is the root.
pub type Ino = u128;

/// A 32-byte BLAKE3 digest (chunk hash, file root or state digest).
pub type Hash = [u8; 32];

/// A 16-byte session identity used only by advisory locks.
pub type Session = [u8; 16];

/// One directory entry name. Names are bytes, not UTF-8.
pub type Name = Vec<u8>;

/// An absolute, slash-separated path. Paths are bytes, not UTF-8.
pub type Path = Vec<u8>;

/// The root inode.
pub const ROOT: Ino = 0;

/// The content chunk size used by the shared schema.
pub const CHUNK_BYTES: u64 = 65_536;

/// The longest accepted path, including the leading slash.
pub const MAX_PATH_BYTES: usize = 4096;

/// The longest accepted single name.
pub const MAX_NAME_BYTES: usize = 255;

const FILEROOT_DOMAIN: &[u8] = b"sm/v1/fileroot64";
const DIR_DOMAIN: &[u8] = b"sm/v1/dir";
const SYMLINK_DOMAIN: &[u8] = b"sm/v1/symlink";
const DIGEST_DOMAIN: &[u8] = b"sm/v1/state-machine\0";

/// The kind of a namespace object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symbolic link.
    Symlink,
}

impl Kind {
    const fn code(self) -> u8 {
        match self {
            Self::File => 0,
            Self::Dir => 1,
            Self::Symlink => 2,
        }
    }
}

/// One object row (`objects` in the shared schema).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    /// Stable identity.
    pub ino: Ino,
    /// File type.
    pub kind: Kind,
    /// Permission bits, already masked to `0o7777`.
    pub mode: u32,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// Modification time, nanoseconds since the Unix epoch.
    pub mtime_ns: u64,
    /// Logical size. `0` for directories; `target.len()` for symlinks.
    pub size: u64,
    /// File-level Merkle root, or the domain root for directories/symlinks.
    pub file_root: Hash,
    /// Link count. `2 + direct subdirectories` for directories.
    pub nlink: u32,
    /// Symlink target; `Some` exactly for [`Kind::Symlink`].
    pub target: Option<Vec<u8>>,
}

/// One chunk reference in a file's ordered content list.
///
/// `len` is the plaintext length. The last chunk may be shorter than
/// [`CHUNK_BYTES`]; every other chunk is exactly [`CHUNK_BYTES`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Chunk {
    /// `BLAKE3(plaintext)`.
    pub hash: Hash,
    /// Plaintext length, `1..=CHUNK_BYTES`.
    pub len: u32,
}

impl Chunk {
    /// Build a chunk reference.
    pub const fn new(hash: Hash, len: u32) -> Self {
        Self { hash, len }
    }
}

/// Attribute changes from `setattr`. `None` means "leave unchanged".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Attrs {
    /// Permission bits.
    pub mode: Option<u32>,
    /// Owner uid.
    pub uid: Option<u32>,
    /// Owner gid.
    pub gid: Option<u32>,
    /// Modification time.
    pub mtime_ns: Option<u64>,
}

/// A partial update to an object row.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObjectPatch {
    /// New permission bits.
    pub mode: Option<u32>,
    /// New owner uid.
    pub uid: Option<u32>,
    /// New owner gid.
    pub gid: Option<u32>,
    /// New modification time.
    pub mtime_ns: Option<u64>,
    /// New logical size. Normally set through [`Change::UpdateChunks`].
    pub size: Option<u64>,
    /// New file root. Normally set through [`Change::UpdateChunks`].
    pub file_root: Option<Hash>,
    /// New link count.
    pub nlink: Option<u32>,
}

/// A POSIX error number.
///
/// The values are the Linux numbers. The type is a thin newtype, matching the
/// store layer's style, so a caller can translate it to `rustix`/FUSE at the
/// edge without this module depending on either.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Errno(pub i32);

impl Errno {
    /// Operation not permitted.
    pub const EPERM: Self = Self(1);
    /// No such file or directory.
    pub const ENOENT: Self = Self(2);
    /// I/O error.
    pub const EIO: Self = Self(5);
    /// Resource temporarily unavailable.
    pub const EAGAIN: Self = Self(11);
    /// Device or resource busy.
    pub const EBUSY: Self = Self(16);
    /// File exists.
    pub const EEXIST: Self = Self(17);
    /// Not a directory.
    pub const ENOTDIR: Self = Self(20);
    /// Is a directory.
    pub const EISDIR: Self = Self(21);
    /// Invalid argument.
    pub const EINVAL: Self = Self(22);
    /// No space left on device.
    pub const ENOSPC: Self = Self(28);
    /// File name too long.
    pub const ENAMETOOLONG: Self = Self(36);
    /// Function not implemented.
    pub const ENOSYS: Self = Self(38);
    /// Directory not empty.
    pub const ENOTEMPTY: Self = Self(39);
    /// Value too large for the data type.
    pub const EOVERFLOW: Self = Self(75);

    /// The raw platform error number.
    pub const fn raw(self) -> i32 {
        self.0
    }

    /// The symbolic name, for logs and test failures.
    pub const fn name(self) -> &'static str {
        match self.0 {
            1 => "EPERM",
            2 => "ENOENT",
            5 => "EIO",
            11 => "EAGAIN",
            16 => "EBUSY",
            17 => "EEXIST",
            20 => "ENOTDIR",
            21 => "EISDIR",
            22 => "EINVAL",
            28 => "ENOSPC",
            36 => "ENAMETOOLONG",
            38 => "ENOSYS",
            39 => "ENOTEMPTY",
            75 => "EOVERFLOW",
            _ => "EUNKNOWN",
        }
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl std::error::Error for Errno {}

/// Why an operation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reject {
    /// The POSIX error the caller should report.
    pub errno: Errno,
    /// A stable, allocation-free explanation for logs and tests.
    pub reason: &'static str,
}

impl Reject {
    /// Build a rejection.
    pub const fn new(errno: Errno, reason: &'static str) -> Self {
        Self { errno, reason }
    }
}

impl fmt::Display for Reject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.errno, self.reason)
    }
}

impl std::error::Error for Reject {}

/// The result of planning one operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Apply these row changes, in order, in one transaction.
    Apply(Vec<Change>),
    /// Apply nothing; report the reason.
    Reject(Reject),
}

impl Verdict {
    /// True when the operation was accepted.
    pub fn is_apply(&self) -> bool {
        matches!(self, Self::Apply(_))
    }

    /// The changes, or an empty slice when rejected.
    pub fn changes(&self) -> &[Change] {
        match self {
            Self::Apply(changes) => changes,
            Self::Reject(_) => &[],
        }
    }
}

/// One row-level change for a SQLite transaction.
///
/// The order is significant. In particular, `InsertObject` precedes
/// `InsertName`, and `RemoveName` precedes `RemoveObject`, so a transaction
/// with immediate foreign-key checks never sees a dangling reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// Insert a new `objects` row.
    InsertObject(Object),
    /// Patch an existing `objects` row.
    UpdateObject {
        /// Target inode.
        ino: Ino,
        /// Fields to change.
        patch: ObjectPatch,
    },
    /// Delete an `objects` row. `object_chunks` rows cascade.
    RemoveObject {
        /// Target inode.
        ino: Ino,
    },
    /// Insert a `names` row.
    InsertName {
        /// Parent directory.
        parent: Ino,
        /// Entry name.
        name: Name,
        /// Child inode.
        ino: Ino,
    },
    /// Delete a `names` row.
    RemoveName {
        /// Parent directory.
        parent: Ino,
        /// Entry name.
        name: Name,
    },
    /// Replace the ordered `object_chunks` list and the object's size/root.
    UpdateChunks {
        /// Target inode.
        ino: Ino,
        /// New ordered chunk references.
        chunks: Vec<Chunk>,
        /// New logical size; must equal the sum of chunk lengths.
        size: u64,
        /// New file-level root; must equal `file_root(&chunks)`.
        file_root: Hash,
    },
    /// Change attributes on an existing object.
    SetAttrs {
        /// Target inode.
        ino: Ino,
        /// Fields to change.
        attrs: Attrs,
    },
    /// Insert one advisory lock.
    InsertLock {
        /// Inode and inclusive byte range.
        key: LockKey,
        /// Holder.
        session: Session,
        /// Lock mode.
        typ: LockType,
    },
    /// Remove one session's locks overlapping an inclusive byte range.
    ///
    /// The SQLite writer deletes every row of `session` on `ino` whose range
    /// intersects `[start, end]`. `plan` re-inserts the non-overlapping left
    /// and right remainders, so a partial unlock trims rather than discards a
    /// larger lock.
    RemoveLocks {
        /// Holder.
        session: Session,
        /// Inode.
        ino: Ino,
        /// First byte, inclusive.
        start: u64,
        /// Last byte, inclusive.
        end: u64,
    },
    /// Remove every lock held by one session.
    RemoveSessionLocks {
        /// Holder.
        session: Session,
    },
}

/// An advisory lock range. `end` is inclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LockKey {
    /// Inode.
    pub ino: Ino,
    /// First byte, inclusive.
    pub start: u64,
    /// Last byte, inclusive. `u64::MAX` means "to end of file".
    pub end: u64,
}

impl LockKey {
    /// True when the two inclusive ranges share at least one byte.
    pub const fn overlaps(self, other: Self) -> bool {
        self.ino == other.ino && self.start <= other.end && other.start <= self.end
    }
}

/// Advisory lock mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LockType {
    /// Shared.
    Read,
    /// Exclusive.
    Write,
}

impl LockType {
    const fn code(self) -> u8 {
        match self {
            Self::Read => 0,
            Self::Write => 1,
        }
    }
}

/// One granted advisory lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lock {
    /// Holder.
    pub session: Session,
    /// Mode.
    pub typ: LockType,
}

/// The complete namespace state.
///
/// `names` is grouped by parent so a lookup borrows the name slice instead of
/// allocating a key. Every map is a `BTreeMap`: iteration order is part of
/// [`State::digest`]'s contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    objects: BTreeMap<Ino, Object>,
    names: BTreeMap<Ino, BTreeMap<Name, Ino>>,
    chunks: BTreeMap<Ino, Vec<Chunk>>,
    locks: BTreeMap<(LockKey, Session), Lock>,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    /// An empty namespace holding only the root directory.
    pub fn new() -> Self {
        let mut objects = BTreeMap::new();
        objects.insert(
            ROOT,
            Object {
                ino: ROOT,
                kind: Kind::Dir,
                mode: 0o755,
                uid: 0,
                gid: 0,
                mtime_ns: 0,
                size: 0,
                file_root: dir_root(),
                nlink: 2,
                target: None,
            },
        );
        Self {
            objects,
            names: BTreeMap::new(),
            chunks: BTreeMap::new(),
            locks: BTreeMap::new(),
        }
    }

    /// Look up one object.
    pub fn object(&self, ino: Ino) -> Option<&Object> {
        self.objects.get(&ino)
    }

    /// The ordered chunk list of a file; empty for other kinds.
    pub fn chunks(&self, ino: Ino) -> &[Chunk] {
        self.chunks.get(&ino).map_or(&[], Vec::as_slice)
    }

    /// Look up one directory entry.
    pub fn lookup(&self, parent: Ino, name: &[u8]) -> Option<Ino> {
        self.names
            .get(&parent)
            .and_then(|entries| entries.get(name))
            .copied()
    }

    /// Resolve an absolute path from the root. Symlinks are not followed.
    ///
    /// # Errors
    ///
    /// `EINVAL` for a malformed path, `ENAMETOOLONG` for an over-long path or
    /// name, `ENOENT` for a missing component, `ENOTDIR` when an intermediate
    /// component is not a directory.
    pub fn resolve(&self, path: &[u8]) -> Result<Ino, Reject> {
        resolve_path(self, path)
    }

    /// The entries of one directory, in name order.
    pub fn children(&self, parent: Ino) -> impl Iterator<Item = (&[u8], Ino)> + '_ {
        self.names
            .get(&parent)
            .into_iter()
            .flat_map(|entries| entries.iter())
            .map(|(name, ino)| (name.as_slice(), *ino))
    }

    /// Every object, in inode order.
    pub fn objects(&self) -> impl Iterator<Item = &Object> + '_ {
        self.objects.values()
    }

    /// Every lock, in key order.
    pub fn locks(&self) -> impl Iterator<Item = (&LockKey, &Lock)> + '_ {
        self.locks.iter().map(|((key, _), lock)| (key, lock))
    }

    /// Number of objects, including the root.
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// True when only the root remains (or the state is corrupt and empty).
    pub fn is_empty(&self) -> bool {
        self.objects.len() <= 1
    }

    /// Plan one operation without changing `self`.
    pub fn plan(&self, op: &Op) -> Verdict {
        plan(op, self)
    }

    /// Plan and apply one operation.
    ///
    /// This is the oracle/test path. A production SQLite writer should use
    /// [`plan`] and execute the returned [`Change`] values itself.
    pub fn apply(&mut self, op: &Op) -> Result<(), Reject> {
        match plan(op, self) {
            Verdict::Apply(changes) => {
                self.commit(changes);
                Ok(())
            }
            Verdict::Reject(reject) => Err(reject),
        }
    }

    /// Apply a planned change list.
    ///
    /// The list must come from [`plan`] on this state. Applying an arbitrary
    /// list is not validated; [`State::check_invariants`] will report damage.
    pub fn commit(&mut self, changes: Vec<Change>) {
        for change in changes {
            match change {
                Change::InsertObject(object) => {
                    let ino = object.ino;
                    let is_file = object.kind == Kind::File;
                    self.objects.insert(ino, object);
                    if is_file {
                        self.chunks.entry(ino).or_default();
                    } else {
                        self.chunks.remove(&ino);
                    }
                }
                Change::UpdateObject { ino, patch } => {
                    if let Some(object) = self.objects.get_mut(&ino) {
                        if let Some(value) = patch.mode {
                            object.mode = value;
                        }
                        if let Some(value) = patch.uid {
                            object.uid = value;
                        }
                        if let Some(value) = patch.gid {
                            object.gid = value;
                        }
                        if let Some(value) = patch.mtime_ns {
                            object.mtime_ns = value;
                        }
                        if let Some(value) = patch.size {
                            object.size = value;
                        }
                        if let Some(value) = patch.file_root {
                            object.file_root = value;
                        }
                        if let Some(value) = patch.nlink {
                            object.nlink = value;
                        }
                    }
                }
                Change::RemoveObject { ino } => {
                    self.objects.remove(&ino);
                    self.chunks.remove(&ino);
                    self.names.retain(|_, entries| {
                        entries.retain(|_, child| *child != ino);
                        !entries.is_empty()
                    });
                    self.locks.retain(|(key, _), _| key.ino != ino);
                }
                Change::InsertName { parent, name, ino } => {
                    self.names.entry(parent).or_default().insert(name, ino);
                }
                Change::RemoveName { parent, name } => {
                    let empty = if let Some(entries) = self.names.get_mut(&parent) {
                        entries.remove(&name);
                        entries.is_empty()
                    } else {
                        false
                    };
                    if empty {
                        self.names.remove(&parent);
                    }
                }
                Change::UpdateChunks {
                    ino,
                    chunks,
                    size,
                    file_root,
                } => {
                    self.chunks.insert(ino, chunks);
                    if let Some(object) = self.objects.get_mut(&ino) {
                        object.size = size;
                        object.file_root = file_root;
                    }
                }
                Change::SetAttrs { ino, attrs } => {
                    if let Some(object) = self.objects.get_mut(&ino) {
                        if let Some(value) = attrs.mode {
                            object.mode = value;
                        }
                        if let Some(value) = attrs.uid {
                            object.uid = value;
                        }
                        if let Some(value) = attrs.gid {
                            object.gid = value;
                        }
                        if let Some(value) = attrs.mtime_ns {
                            object.mtime_ns = value;
                        }
                    }
                }
                Change::InsertLock { key, session, typ } => {
                    self.locks.insert((key, session), Lock { session, typ });
                }
                Change::RemoveLocks {
                    session,
                    ino,
                    start,
                    end,
                } => {
                    self.locks.retain(|(key, holder), _| {
                        !(*holder == session
                            && key.ino == ino
                            && key.start <= end
                            && start <= key.end)
                    });
                }
                Change::RemoveSessionLocks { session } => {
                    self.locks.retain(|(_, holder), _| *holder != session);
                }
            }
        }
    }

    /// A deterministic digest of the whole state.
    ///
    /// This is a test and diagnostics value, not the schema's `state_hash`
    /// (which sorts by canonical path). Equal states produce equal digests on
    /// every platform and every run.
    pub fn digest(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(&(self.objects.len() as u64).to_le_bytes());
        for (ino, object) in &self.objects {
            hasher.update(&ino.to_le_bytes());
            hasher.update(&[object.kind.code()]);
            hasher.update(&object.mode.to_le_bytes());
            hasher.update(&object.uid.to_le_bytes());
            hasher.update(&object.gid.to_le_bytes());
            hasher.update(&object.mtime_ns.to_le_bytes());
            hasher.update(&object.size.to_le_bytes());
            hasher.update(&object.file_root);
            hasher.update(&object.nlink.to_le_bytes());
            match &object.target {
                Some(target) => {
                    hasher.update(&[1]);
                    hasher.update(&(target.len() as u64).to_le_bytes());
                    hasher.update(target);
                }
                None => {
                    hasher.update(&[0]);
                }
            }
        }
        hasher.update(&(self.names.len() as u64).to_le_bytes());
        for (parent, entries) in &self.names {
            hasher.update(&parent.to_le_bytes());
            hasher.update(&(entries.len() as u64).to_le_bytes());
            for (name, ino) in entries {
                hasher.update(&(name.len() as u64).to_le_bytes());
                hasher.update(name);
                hasher.update(&ino.to_le_bytes());
            }
        }
        hasher.update(&(self.chunks.len() as u64).to_le_bytes());
        for (ino, chunks) in &self.chunks {
            hasher.update(&ino.to_le_bytes());
            hasher.update(&(chunks.len() as u64).to_le_bytes());
            for chunk in chunks {
                hasher.update(&chunk.hash);
                hasher.update(&chunk.len.to_le_bytes());
            }
        }
        hasher.update(&(self.locks.len() as u64).to_le_bytes());
        for ((key, session), lock) in &self.locks {
            hasher.update(&key.ino.to_le_bytes());
            hasher.update(&key.start.to_le_bytes());
            hasher.update(&key.end.to_le_bytes());
            hasher.update(session);
            hasher.update(&[lock.typ.code()]);
        }
        *hasher.finalize().as_bytes()
    }

    /// Check every structural invariant. Returns a static reason on failure.
    pub fn check_invariants(&self) -> Result<(), &'static str> {
        let root = self.objects.get(&ROOT).ok_or("root object missing")?;
        if root.kind != Kind::Dir {
            return Err("root is not a directory");
        }
        if root.size != 0 {
            return Err("root has a size");
        }
        if root.target.is_some() {
            return Err("root has a target");
        }
        if root.file_root != dir_root() {
            return Err("root file_root is not the directory root");
        }
        let root_children = self.child_dirs(ROOT);
        if root.nlink != 2u32.saturating_add(root_children) {
            return Err("root nlink does not match its subdirectories");
        }

        for (ino, object) in &self.objects {
            if *ino == ROOT {
                continue;
            }
            let name_count = self
                .names
                .values()
                .flat_map(|entries| entries.values())
                .filter(|child| *child == ino)
                .count() as u64;
            if name_count == 0 {
                return Err("object has no name");
            }
            match object.kind {
                Kind::File => {
                    if u64::from(object.nlink) != name_count {
                        return Err("file nlink does not match its names");
                    }
                    if object.target.is_some() {
                        return Err("file carries a target");
                    }
                    let (size, root) = match validate_chunks(self.chunks(*ino)) {
                        Ok(value) => value,
                        Err(_) => return Err("file chunks are malformed"),
                    };
                    if object.size != size {
                        return Err("file size does not match its chunks");
                    }
                    if object.file_root != root {
                        return Err("file file_root does not match its chunks");
                    }
                }
                Kind::Dir => {
                    if name_count != 1 {
                        return Err("directory does not have exactly one name");
                    }
                    if object.target.is_some() {
                        return Err("directory carries a target");
                    }
                    if object.size != 0 {
                        return Err("directory has a size");
                    }
                    if object.file_root != dir_root() {
                        return Err("directory file_root is not the directory root");
                    }
                    if !self.chunks(*ino).is_empty() {
                        return Err("directory has chunks");
                    }
                    let children = self.child_dirs(*ino);
                    if object.nlink != 2u32.saturating_add(children) {
                        return Err("directory nlink does not match its subdirectories");
                    }
                }
                Kind::Symlink => {
                    if u64::from(object.nlink) != name_count {
                        return Err("symlink nlink does not match its names");
                    }
                    let Some(target) = &object.target else {
                        return Err("symlink has no target");
                    };
                    if target.is_empty() {
                        return Err("symlink target is empty");
                    }
                    if target.len() > MAX_PATH_BYTES {
                        return Err("symlink target is too long");
                    }
                    if target.contains(&0) {
                        return Err("symlink target contains NUL");
                    }
                    if object.size != target.len() as u64 {
                        return Err("symlink size does not match its target");
                    }
                    if object.file_root != symlink_root(target) {
                        return Err("symlink file_root does not match its target");
                    }
                    if !self.chunks(*ino).is_empty() {
                        return Err("symlink has chunks");
                    }
                }
            }
        }

        for (parent, entries) in &self.names {
            let parent_object = self
                .objects
                .get(parent)
                .ok_or("name parent does not exist")?;
            if parent_object.kind != Kind::Dir {
                return Err("name parent is not a directory");
            }
            for (name, child) in entries {
                if name.is_empty() || name.len() > MAX_NAME_BYTES {
                    return Err("name length is invalid");
                }
                if name.contains(&b'/') || name.contains(&0) {
                    return Err("name contains an invalid byte");
                }
                if *child == ROOT {
                    return Err("root has a name");
                }
                if !self.objects.contains_key(child) {
                    return Err("name child does not exist");
                }
            }
        }

        for ino in self.chunks.keys() {
            if !self.objects.contains_key(ino) {
                return Err("chunk owner does not exist");
            }
        }

        for ((key, session), lock) in &self.locks {
            if key.start > key.end {
                return Err("lock range is inverted");
            }
            if !self.objects.contains_key(&key.ino) {
                return Err("lock inode does not exist");
            }
            if lock.session != *session {
                return Err("lock holder does not match its key");
            }
        }

        for (ino, object) in &self.objects {
            if object.kind != Kind::Dir {
                continue;
            }
            let mut node = *ino;
            let mut steps = 0usize;
            loop {
                if node == ROOT {
                    break;
                }
                let Some(parent) = self.parent_of(node) else {
                    break;
                };
                node = parent;
                steps += 1;
                if steps > self.objects.len() {
                    return Err("directory cycle");
                }
            }
        }

        Ok(())
    }

    fn child_dirs(&self, dir: Ino) -> u32 {
        self.names
            .get(&dir)
            .into_iter()
            .flat_map(|entries| entries.values())
            .filter(|child| {
                self.objects
                    .get(*child)
                    .is_some_and(|object| object.kind == Kind::Dir)
            })
            .count() as u32
    }

    pub(crate) fn parent_of(&self, node: Ino) -> Option<Ino> {
        self.names.iter().find_map(|(parent, entries)| {
            entries
                .values()
                .any(|child| *child == node)
                .then_some(*parent)
        })
    }
}

/// The `file_root` of an ordered chunk list.
///
/// ```text
/// BLAKE3("sm/v1/fileroot64" || block_count_le64
///        || concat(chunk_no_le32 || chunk_hash))
/// ```
pub fn file_root(chunks: &[Chunk]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FILEROOT_DOMAIN);
    hasher.update(&(chunks.len() as u64).to_le_bytes());
    for (index, chunk) in chunks.iter().enumerate() {
        hasher.update(&(index as u32).to_le_bytes());
        hasher.update(&chunk.hash);
    }
    *hasher.finalize().as_bytes()
}

/// The fixed `file_root` of an empty file.
pub fn empty_file_root() -> Hash {
    file_root(&[])
}

/// The fixed `file_root` of a directory.
pub fn dir_root() -> Hash {
    *blake3::hash(DIR_DOMAIN).as_bytes()
}

/// The `file_root` of a symlink target.
pub fn symlink_root(target: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SYMLINK_DOMAIN);
    hasher.update(target);
    *hasher.finalize().as_bytes()
}

/// Validate a file's chunk list and return `(size, file_root)`.
///
/// Rules: the empty list is the empty file; every chunk is `1..=CHUNK_BYTES`;
/// every chunk except the last is exactly `CHUNK_BYTES`; the chunk count is
/// `ceil(size / CHUNK_BYTES)`; and the total length fits in `u64`.
///
/// # Errors
///
/// `EINVAL` for a malformed list, `EOVERFLOW` for an unrepresentable total.
pub fn validate_chunks(chunks: &[Chunk]) -> Result<(u64, Hash), Reject> {
    if chunks.len() > u32::MAX as usize {
        return Err(Reject::new(Errno::EOVERFLOW, "too many chunks"));
    }
    let mut size = 0u64;
    for (index, chunk) in chunks.iter().enumerate() {
        if chunk.len == 0 {
            return Err(Reject::new(Errno::EINVAL, "zero-length chunk"));
        }
        if u64::from(chunk.len) > CHUNK_BYTES {
            return Err(Reject::new(Errno::EINVAL, "chunk exceeds 64 KiB"));
        }
        if index + 1 != chunks.len() && u64::from(chunk.len) != CHUNK_BYTES {
            return Err(Reject::new(
                Errno::EINVAL,
                "non-final chunk is shorter than 64 KiB",
            ));
        }
        size = size
            .checked_add(u64::from(chunk.len))
            .ok_or_else(|| Reject::new(Errno::EOVERFLOW, "file size overflows u64"))?;
    }
    if size.div_ceil(CHUNK_BYTES) != chunks.len() as u64 {
        return Err(Reject::new(
            Errno::EINVAL,
            "chunk count does not match file size",
        ));
    }
    Ok((size, file_root(chunks)))
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

pub(crate) fn split_path(path: &[u8]) -> Result<Vec<&[u8]>, Reject> {
    if path.is_empty() {
        return Err(Reject::new(Errno::EINVAL, "empty path"));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(Reject::new(Errno::ENAMETOOLONG, "path too long"));
    }
    if path[0] != b'/' {
        return Err(Reject::new(Errno::EINVAL, "path is not absolute"));
    }
    if path == b"/" {
        return Ok(Vec::new());
    }
    if path.ends_with(b"/") {
        return Err(Reject::new(Errno::EINVAL, "path has a trailing slash"));
    }
    let mut segments = Vec::new();
    for segment in path[1..].split(|byte| *byte == b'/') {
        if segment.is_empty() {
            return Err(Reject::new(Errno::EINVAL, "path has an empty component"));
        }
        if segment == b"." || segment == b".." {
            return Err(Reject::new(Errno::EINVAL, "path has a dot component"));
        }
        if segment.len() > MAX_NAME_BYTES {
            return Err(Reject::new(Errno::ENAMETOOLONG, "name too long"));
        }
        if segment.contains(&0) {
            return Err(Reject::new(Errno::EINVAL, "path contains NUL"));
        }
        segments.push(segment);
    }
    Ok(segments)
}

pub(crate) fn resolve_path(state: &State, path: &[u8]) -> Result<Ino, Reject> {
    let segments = split_path(path)?;
    let mut current = ROOT;
    for segment in segments {
        current = step(state, current, segment)?;
    }
    Ok(current)
}

pub(crate) fn resolve_parent(state: &State, path: &[u8]) -> Result<(Ino, Name), Reject> {
    let segments = split_path(path)?;
    let Some((name, parents)) = segments.split_last() else {
        return Err(Reject::new(Errno::EINVAL, "root has no parent"));
    };
    let mut current = ROOT;
    for segment in parents {
        current = step(state, current, segment)?;
    }
    let parent = state
        .object(current)
        .ok_or_else(|| Reject::new(Errno::ENOENT, "parent does not exist"))?;
    if parent.kind != Kind::Dir {
        return Err(Reject::new(Errno::ENOTDIR, "parent is not a directory"));
    }
    Ok((current, name.to_vec()))
}

pub(crate) fn step(state: &State, dir: Ino, name: &[u8]) -> Result<Ino, Reject> {
    let object = state
        .object(dir)
        .ok_or_else(|| Reject::new(Errno::ENOENT, "directory does not exist"))?;
    if object.kind != Kind::Dir {
        return Err(Reject::new(Errno::ENOTDIR, "component is not a directory"));
    }
    state
        .lookup(dir, name)
        .ok_or_else(|| Reject::new(Errno::ENOENT, "name does not exist"))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tests_impl;
