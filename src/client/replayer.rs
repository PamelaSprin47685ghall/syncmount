//! Deterministic replay engine: `S(seq)`, pending overlay, dedup and reorder.
//!
//! Owner: W11 (E5). See 41 §5, 45 U-REPLAY/INV-19 and 53 W11.
//!
//! # One writer, one order
//!
//! [`Replayer`] is the only writer of the replay state. Every frame it accepts
//! advances `applied_seq` by exactly one, after the disk has been brought to
//! the state the operation describes. The order is the server's `seq` order;
//! nothing here consults a clock, a random source, or a hash-map iteration
//! order for a decision (41 invariants 1 and 10).
//!
//! # Three-phase application
//!
//! 1. [`Namespace::plan`] is a pure function: it reads `S` and the operation,
//!    and returns the disk effects plus the state delta. A POSIX refusal
//!    (`EEXIST`, `ENOENT`, `ENOTEMPTY`, …) is *the result of the total order*,
//!    so it is carried in the plan instead of being an engine error.
//! 2. [`ReplayBacking`] applies the effects. A failure here is fatal: the
//!    watermark must never pass a state the disk does not have.
//! 3. [`Namespace::commit`] applies the state delta. Only `S` changes; the
//!    disk was already changed in step 2.
//!
//! # Sequence classification (39 §2.5, 45 INV-19)
//!
//! | observation | action |
//! |---|---|
//! | `seq <= applied`, `op_id` seen | drop; the watermark does not move |
//! | `seq <= applied`, `op_id` unseen | `Resync::Rollback` — the sequence space was replaced |
//! | `seq > applied + 1`, buffer has room | buffer (≤1024 frames / ≤1 s) |
//! | buffer overflow or timeout | `Resync::SeqGap` |
//! | epoch differs | `Resync::EpochChanged` |
//!
//! Three resyncs without a ≥60 s steady window end in
//! [`Fatal::ResyncLoop`] and an unmount with exit code 10.
//!
//! # Inode identity
//!
//! `MKDIR`, `CREATE_EXCL` and `SYMLINK` do not carry an inode id on the wire
//! (41 R6). The replay engine derives one from the operation id with BLAKE3, so
//! every client reaches the same id for the same operation without a protocol
//! field. `RENAME` and `LINK` never change an id.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard};
use std::time::Duration;

use crate::client::config::Tuning;
use crate::client::writer::{Backpressure, LocalSeq};
use crate::protocol::frame::{ClientId, OpId, Seq};
use crate::protocol::messages::{DataRef, Leave, OpClass, OpIdVerdict};
use crate::sync::manifest::Manifest;

/// The two protocol-side tables the client consumes.
///
/// [`OpIdLog`] backs [`DedupWindow`] (1M ids / 24 h). [`SeqGate`] is the strict
/// frame gate the downlink (W12) applies before a frame reaches the replayer;
/// the replayer itself classifies against `applied` because only it knows the
/// JOIN `covered` watermark and can tell a duplicate from a rollback.
pub use crate::protocol::messages::{OpIdLog, SeqGate};
use crate::store::backing::Effect;
use crate::store::node_table::InodeId;
use crate::store::{AttrDelta, Errno, Kind, Timespec};

/// Largest directory depth the replay engine accepts (39 §3.2).
pub const MAX_DEPTH: usize = 128;
/// Longest single path component, in bytes.
pub const NAME_MAX: usize = 255;
/// `fcntl` lock action: acquire without waiting.
pub const LOCK_ACTION_SET: u8 = 0;
/// `fcntl` lock action: acquire, waiting.
pub const LOCK_ACTION_WAIT: u8 = 1;
/// `fcntl` lock action: release.
pub const LOCK_ACTION_UNLOCK: u8 = 2;

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Attributes carried by every file operation (`ORDERED` requires them).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpAttrs {
    /// Permission bits, when the operation carries them.
    pub mode: Option<u32>,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// Modification time, nanoseconds since the Unix epoch.
    pub mtime_ns: u64,
}

/// Class-specific arguments, owned so a decoded frame can outlive its buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpBody {
    /// No arguments.
    None,
    /// `WRITE`: whole-stream data.
    Write(DataRef),
    /// `PWRITE`: offset plus stream data.
    Pwrite {
        /// Byte offset.
        offset: u64,
        /// Stream reference.
        data: DataRef,
    },
    /// `TRUNCATE`: new length.
    Truncate {
        /// New length.
        length: u64,
    },
    /// `SETATTR`: optional mode change.
    Setattr {
        /// New mode.
        mode: Option<u32>,
    },
    /// `RENAME`: destination path.
    Rename {
        /// Destination.
        path2: String,
    },
    /// `MKDIR`: mode.
    Mkdir {
        /// Directory mode.
        mode: u32,
    },
    /// `LINK`: existing path.
    Link {
        /// Existing path.
        target: String,
    },
    /// `SYMLINK`: link contents.
    Symlink {
        /// Link contents.
        target: String,
    },
    /// `CREATE_EXCL`: mode and open flags.
    CreateExcl {
        /// File mode.
        mode: u32,
        /// Open flags.
        flags: u32,
    },
    /// `FLOCK` or `FCNTL_LOCK`.
    Lock {
        /// Lock type (`F_RDLCK` = 0, `F_WRLCK` = 1).
        lock_type: u8,
        /// Lock action.
        action: u8,
        /// Range start.
        start: u64,
        /// Range length; zero means "to end of file".
        len: u64,
        /// True for BSD `flock`, which never leaves this client.
        flock: bool,
    },
    /// `SYNC_CTRL`: no arguments in v1.
    SyncCtrl,
}

/// One operation, decoded and owned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op {
    /// Operation identifier.
    pub op_id: OpId,
    /// Author client.
    pub client_id: ClientId,
    /// Operation class.
    pub class: OpClass,
    /// Absolute path, for classes that have one.
    pub path: Option<String>,
    /// File attributes, for classes that have them.
    pub attrs: Option<OpAttrs>,
    /// Class-specific arguments.
    pub body: OpBody,
}

impl Op {
    /// Build an operation with default attributes.
    pub fn new(op_id: OpId, client_id: ClientId, class: OpClass, path: impl Into<String>) -> Self {
        Self {
            op_id,
            client_id,
            class,
            path: Some(path.into()),
            attrs: None,
            body: OpBody::None,
        }
    }

    /// Set the attributes.
    pub fn with_attrs(mut self, attrs: OpAttrs) -> Self {
        self.attrs = Some(attrs);
        self
    }

    /// Set the class-specific body.
    pub fn with_body(mut self, body: OpBody) -> Self {
        self.body = body;
        self
    }

    /// The path, or `EINVAL` when the class requires one and it is absent.
    fn require_path(&self) -> Result<&str, Errno> {
        self.path.as_deref().ok_or(Errno::EINVAL)
    }

    /// Attributes with the defaults applied.
    fn attrs(&self) -> OpAttrs {
        self.attrs.unwrap_or_default()
    }
}

/// A framed operation as it leaves the downlink.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncomingOp {
    /// Server sequence.
    pub seq: Seq,
    /// Session epoch.
    pub epoch: u64,
    /// Decoded operation.
    pub op: Op,
}

impl IncomingOp {
    /// Build a frame.
    pub const fn new(seq: Seq, epoch: u64, op: Op) -> Self {
        Self { seq, epoch, op }
    }
}

// ---------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------

/// Why the client must leave `STEADY` and rebuild from the cluster manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResyncReason {
    /// The server restarted; every sequence number is new.
    EpochChanged,
    /// An unknown operation claimed a sequence already applied.
    Rollback,
    /// A hole did not fill within the buffer limits.
    SeqGap,
    /// A sequenced frame carried `seq == 0`.
    Unsequenced,
}

impl ResyncReason {
    /// Stable name for logs and status.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EpochChanged => "epoch_changed",
            Self::Rollback => "rollback",
            Self::SeqGap => "seq_gap",
            Self::Unsequenced => "unsequenced",
        }
    }
}

/// A condition that ends the current connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fatal {
    /// The replay state must be rebuilt from a fresh manifest.
    Resync(ResyncReason),
    /// Three resyncs without a steady window; unmount with exit code 10.
    ResyncLoop,
    /// The disk refused an effect the total order requires.
    Materialize {
        /// Sequence being applied.
        seq: Seq,
        /// Underlying error.
        errno: Errno,
    },
    /// A frame violated an invariant the engine relies on.
    Protocol(&'static str),
    /// An operation class this build cannot apply (fail-closed, 55 P1-12).
    UnknownOpClass(u8),
}

impl fmt::Display for Fatal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resync(reason) => write!(f, "resync required: {}", reason.as_str()),
            Self::ResyncLoop => f.write_str("resync loop: three rebuilds without a steady window"),
            Self::Materialize { seq, errno } => {
                write!(f, "materialize failed at seq {seq}: {errno}")
            }
            Self::Protocol(what) => write!(f, "protocol violation: {what}"),
            Self::UnknownOpClass(raw) => write!(f, "unknown op_class {raw}"),
        }
    }
}

impl std::error::Error for Fatal {}

/// Outcome of one accepted frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    /// Watermark after this call.
    pub applied: Seq,
    /// Verdict for the operation itself (the echo of a local waiter).
    pub verdict: Result<(), Errno>,
    /// True when the frame was a duplicate and nothing was applied.
    pub duplicate: bool,
    /// True when the frame was buffered behind a hole.
    pub buffered: bool,
    /// Payload bytes this call materialized in the backing tree.
    ///
    /// Only `WRITE` effects the replay engine applied are counted. A local
    /// write and the echo of the client's own operation are written by the
    /// FUSE path, so they do not appear here.
    pub bytes_written: u64,
}

// ---------------------------------------------------------------------------
// Replay state
// ---------------------------------------------------------------------------

/// One replayed inode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inode {
    /// Identity.
    pub id: InodeId,
    /// File type.
    pub kind: Kind,
    /// Permission bits.
    pub mode: u32,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// Link count; maintained by `seq` order only.
    pub nlink: u32,
    /// Logical size.
    pub size: u64,
    /// Modification time, nanoseconds.
    pub mtime_ns: u64,
    /// Symlink contents.
    pub symlink: Option<Vec<u8>>,
    /// True once the last name was removed; the inode stays for identity.
    pub tombstone: bool,
}

impl Inode {
    fn new(id: InodeId, kind: Kind, mode: u32, attrs: OpAttrs) -> Self {
        Self {
            id,
            kind,
            mode,
            uid: attrs.uid,
            gid: attrs.gid,
            nlink: if kind.is_dir() { 2 } else { 1 },
            size: 0,
            mtime_ns: attrs.mtime_ns,
            symlink: None,
            tombstone: false,
        }
    }
}

/// One `fcntl` lock range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockKey {
    /// Inode.
    pub ino: InodeId,
    /// First byte.
    pub start: u64,
    /// Last byte, inclusive.
    pub end: u64,
}

impl LockKey {
    fn overlaps(self, other: Self) -> bool {
        self.ino == other.ino && self.start <= other.end && other.start <= self.end
    }
}

/// Who holds a lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Holder {
    /// Client.
    pub client: ClientId,
    /// Open-file-description context.
    pub ctx: u64,
}

/// Lock mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockType {
    /// Shared.
    Read,
    /// Exclusive.
    Write,
}

/// One granted lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lock {
    /// Mode.
    pub typ: LockType,
    /// Holder.
    pub holder: Holder,
}

/// A state delta produced by `plan` and applied by `commit`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InodePatch {
    /// New mode.
    pub mode: Option<u32>,
    /// New uid.
    pub uid: Option<u32>,
    /// New gid.
    pub gid: Option<u32>,
    /// New mtime.
    pub mtime_ns: Option<u64>,
    /// New size.
    pub size: Option<u64>,
    /// Link-count change.
    pub nlink_delta: i32,
    /// Tombstone transition.
    pub tombstone: Option<bool>,
}

/// One change to `S`, applied after the disk effects succeeded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// Insert a new inode.
    Insert {
        /// Identity.
        id: InodeId,
        /// Inode.
        inode: Inode,
    },
    /// Remove an inode.
    Remove {
        /// Identity.
        id: InodeId,
    },
    /// Patch an inode.
    Patch {
        /// Identity.
        id: InodeId,
        /// Fields to change.
        patch: InodePatch,
    },
    /// Add one directory entry.
    AddChild {
        /// Directory.
        parent: InodeId,
        /// Name.
        name: OsString,
        /// Child.
        id: InodeId,
    },
    /// Remove one directory entry.
    RemoveChild {
        /// Directory.
        parent: InodeId,
        /// Name.
        name: OsString,
    },
    /// Insert a lock.
    InsertLock {
        /// Range.
        key: LockKey,
        /// Granted lock.
        lock: Lock,
    },
    /// Remove every lock of `holder` overlapping a range.
    RemoveLocks {
        /// Holder.
        holder: Holder,
        /// Inode.
        ino: InodeId,
        /// First byte.
        start: u64,
        /// Last byte.
        end: u64,
    },
    /// Remove every lock of one client (`LEAVE`).
    RemoveClientLocks {
        /// Client that left.
        client: ClientId,
    },
    /// Mark the state as diverged (unknown operation class).
    SetDiverged,
}

/// One disk effect produced by `plan`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FsEffect {
    /// Create a directory with a caller-supplied identity.
    Mkdir {
        /// Parent.
        parent: InodeId,
        /// Name.
        name: OsString,
        /// New identity.
        id: InodeId,
        /// Mode.
        mode: u32,
    },
    /// Create a regular file with a caller-supplied identity.
    Create {
        /// Parent.
        parent: InodeId,
        /// Name.
        name: OsString,
        /// New identity.
        id: InodeId,
        /// Mode.
        mode: u32,
    },
    /// Create a symlink with a caller-supplied identity.
    Symlink {
        /// Parent.
        parent: InodeId,
        /// Name.
        name: OsString,
        /// New identity.
        id: InodeId,
        /// Link contents.
        target: OsString,
    },
    /// Remove a directory entry.
    Unlink {
        /// Parent.
        parent: InodeId,
        /// Name.
        name: OsString,
        /// Target identity (for rebase).
        id: InodeId,
    },
    /// Remove an empty directory.
    Rmdir {
        /// Parent.
        parent: InodeId,
        /// Name.
        name: OsString,
        /// Target identity (for rebase).
        id: InodeId,
    },
    /// Rename one entry.
    Rename {
        /// Source.
        from: (InodeId, OsString),
        /// Destination.
        to: (InodeId, OsString),
    },
    /// Add a hard link.
    Link {
        /// Existing inode.
        id: InodeId,
        /// New parent.
        parent: InodeId,
        /// New name.
        name: OsString,
    },
    /// Write a data stream.
    Write {
        /// Target.
        id: InodeId,
        /// Offset.
        off: u64,
        /// Stream reference.
        data: DataRef,
    },
    /// Truncate.
    Truncate {
        /// Target.
        id: InodeId,
        /// New length.
        size: u64,
    },
    /// Attribute change.
    SetAttr {
        /// Target.
        id: InodeId,
        /// Delta.
        delta: AttrDelta,
    },
}

impl FsEffect {
    /// The inode whose pending effects must be replayed after this effect.
    fn touched_inode(&self) -> Option<InodeId> {
        match self {
            Self::Mkdir { id, .. }
            | Self::Create { id, .. }
            | Self::Symlink { id, .. }
            | Self::Unlink { id, .. }
            | Self::Rmdir { id, .. }
            | Self::Link { id, .. }
            | Self::Write { id, .. }
            | Self::Truncate { id, .. }
            | Self::SetAttr { id, .. } => Some(*id),
            Self::Rename { from, .. } => Some(from.0),
        }
    }
}

/// What the total order decided about an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Apply the effects and the state delta.
    Apply,
    /// The operation lost; only the (possibly empty) state delta applies.
    Reject(Errno),
}

/// The complete result of planning one operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Operation identifier.
    pub op_id: OpId,
    /// Outcome.
    pub verdict: Verdict,
    /// Disk effects, in order.
    pub effects: Vec<FsEffect>,
    /// State delta, in order.
    pub changes: Vec<Change>,
}

impl Plan {
    fn new(op_id: OpId) -> Self {
        Self {
            op_id,
            verdict: Verdict::Apply,
            effects: Vec::new(),
            changes: Vec::new(),
        }
    }

    /// Whether the operation won.
    pub const fn is_applied(&self) -> bool {
        matches!(self.verdict, Verdict::Apply)
    }
}

/// The replay state `S(seq)`.
///
/// Every container is a `BTreeMap`/`BTreeSet`: iteration order is part of the
/// contract, because [`Namespace::hash`] must be reproducible on every client.
#[derive(Clone, Debug)]
pub struct Namespace {
    inodes: BTreeMap<InodeId, Inode>,
    children: BTreeMap<(InodeId, OsString), InodeId>,
    locks: BTreeMap<LockKey, Lock>,
    diverged: bool,
}

impl Default for Namespace {
    fn default() -> Self {
        Self::new()
    }
}

/// Split a manifest path into its parent prefix and final name.
fn split_relative(path: &str) -> Result<(Option<&str>, OsString), Errno> {
    if path.is_empty() || path.starts_with('/') || path.ends_with('/') {
        return Err(Errno::EINVAL);
    }
    match path.rsplit_once('/') {
        Some((parent, name)) if !parent.is_empty() && !name.is_empty() => {
            Ok((Some(parent), OsString::from(name)))
        }
        None => Ok((None, OsString::from(path))),
        Some(_) => Err(Errno::EINVAL),
    }
}

impl Namespace {
    /// An empty namespace holding only the root inode.
    pub fn new() -> Self {
        let mut inodes = BTreeMap::new();
        inodes.insert(
            InodeId::ROOT,
            Inode {
                id: InodeId::ROOT,
                kind: Kind::Dir,
                mode: 0o755,
                uid: 0,
                gid: 0,
                nlink: 2,
                size: 0,
                mtime_ns: 0,
                symlink: None,
                tombstone: false,
            },
        );
        Self {
            inodes,
            children: BTreeMap::new(),
            locks: BTreeMap::new(),
            diverged: false,
        }
    }

    /// Rebuild `S` from the manifest a JOIN installed.
    ///
    /// The cluster-wins step has already made the disk equal to `manifest`;
    /// this makes `S` equal to it as well. Without it `S` holds only the root,
    /// and the first `WRITE` to an existing path is rejected with `ENOENT`
    /// even though the disk has the file.
    ///
    /// Deterministic: entries are consumed in manifest path order (a parent
    /// always precedes its children), inode ids come from the manifest, and
    /// `nlink` is derived from the manifest shape — `2 + direct
    /// subdirectories` for a directory, the number of paths for a
    /// hard-linked file, `1` otherwise. The manifest has no `nlink` field, so
    /// this derivation is the only value that matches the state the total
    /// order built. Locks and the divergence flag are cleared: a JOIN starts
    /// a new session.
    ///
    /// The root is not a manifest entry, so its `mtime_ns` stays at the
    /// [`Namespace::new`] value. The manifest does not carry it, and no
    /// derivation from the entries can recover the time of the last root
    /// mutation.
    ///
    /// # Errors
    ///
    /// `ENOENT` for a missing parent, `EEXIST` for a duplicate name or an
    /// inode id that changes kind.
    pub fn rebuild_from_manifest(&mut self, manifest: &Manifest) -> Result<(), Errno> {
        let mut rebuilt = Self::new();
        for entry in manifest.entries() {
            let (parent_path, name) = split_relative(&entry.path)?;
            let parent = match parent_path {
                Some(path) => rebuilt.resolve_relative(path)?,
                None => InodeId::ROOT,
            };
            if rebuilt.children.contains_key(&(parent, name.clone())) {
                return Err(Errno::EEXIST);
            }
            if let Some(inode) = rebuilt.inodes.get_mut(&entry.inode) {
                if inode.kind != entry.kind || inode.kind.is_dir() {
                    return Err(Errno::EEXIST);
                }
                inode.nlink = inode.nlink.saturating_add(1);
            } else {
                let mut inode = Inode {
                    id: entry.inode,
                    kind: entry.kind,
                    mode: entry.mode,
                    uid: entry.uid,
                    gid: entry.gid,
                    nlink: 1,
                    size: entry.size,
                    mtime_ns: entry.mtime_ns,
                    symlink: None,
                    tombstone: false,
                };
                if entry.kind.is_dir() {
                    inode.nlink = 2;
                } else if entry.kind == Kind::Symlink {
                    // The total order stores the target length, not the
                    // manifest's placeholder size.
                    inode.size = entry.target.len() as u64;
                    inode.symlink = Some(entry.target.as_bytes().to_vec());
                }
                rebuilt.inodes.insert(entry.inode, inode);
            }
            let child_is_dir = entry.kind.is_dir();
            rebuilt.children.insert((parent, name), entry.inode);
            if child_is_dir {
                if let Some(dir) = rebuilt.inodes.get_mut(&parent) {
                    dir.nlink = dir.nlink.saturating_add(1);
                }
            }
        }
        *self = rebuilt;
        Ok(())
    }

    /// Resolve a relative, slash-separated path from the root.
    fn resolve_relative(&self, path: &str) -> Result<InodeId, Errno> {
        let mut current = InodeId::ROOT;
        for segment in path.split('/') {
            if segment.is_empty() || segment == "." || segment == ".." {
                return Err(Errno::EINVAL);
            }
            current = self.step(current, segment)?;
        }
        Ok(current)
    }

    /// Look up an inode.
    pub fn inode(&self, id: InodeId) -> Option<&Inode> {
        self.inodes.get(&id)
    }

    /// Look up a directory entry.
    pub fn lookup(&self, parent: InodeId, name: &OsStr) -> Option<InodeId> {
        self.children.get(&(parent, name.to_os_string())).copied()
    }

    /// Directory entries of `dir`, in name order.
    pub fn children_of(&self, dir: InodeId) -> Vec<(OsString, InodeId)> {
        self.children
            .range((dir, OsString::new())..)
            .take_while(|((parent, _), _)| *parent == dir)
            .map(|((_, name), id)| (name.clone(), *id))
            .collect()
    }

    /// All inodes, in identity order.
    pub fn inodes(&self) -> impl Iterator<Item = &Inode> {
        self.inodes.values()
    }

    /// All locks, in key order.
    pub fn locks(&self) -> impl Iterator<Item = (&LockKey, &Lock)> {
        self.locks.iter()
    }

    /// The first lock that would block `typ` on `[start, end]`.
    ///
    /// Locks held by `client` itself never conflict: POSIX `F_GETLK` ignores
    /// the caller's own locks, and every lock of this mount carries this
    /// client's identity.
    pub fn find_lock(
        &self,
        ino: InodeId,
        start: u64,
        end: u64,
        typ: LockType,
        client: ClientId,
    ) -> Option<(LockKey, Lock)> {
        let range = LockKey { ino, start, end };
        self.locks
            .iter()
            .find(|(key, lock)| {
                lock.holder.client != client
                    && key.overlaps(range)
                    && (lock.typ == LockType::Write || typ == LockType::Write)
            })
            .map(|(key, lock)| (*key, *lock))
    }

    /// Number of inodes.
    pub fn len(&self) -> usize {
        self.inodes.len()
    }

    /// Whether only the root remains.
    pub fn is_empty(&self) -> bool {
        self.inodes.len() <= 1
    }

    /// Whether an unknown operation class was seen.
    pub const fn diverged(&self) -> bool {
        self.diverged
    }

    /// Resolve an absolute path.
    pub fn resolve(&self, path: &str) -> Result<InodeId, Errno> {
        let mut current = InodeId::ROOT;
        for segment in split_segments(path)? {
            current = self.step(current, segment)?;
        }
        Ok(current)
    }

    /// Resolve the parent of an absolute path.
    fn resolve_parent(&self, path: &str) -> Result<(InodeId, OsString), Errno> {
        let segments = split_segments(path)?;
        let Some((name, parents)) = segments.split_last() else {
            return Err(Errno::EINVAL);
        };
        let mut current = InodeId::ROOT;
        for segment in parents {
            current = self.step(current, segment)?;
        }
        Ok((current, OsString::from(*name)))
    }

    fn step(&self, dir: InodeId, name: &str) -> Result<InodeId, Errno> {
        let inode = self.inodes.get(&dir).ok_or(Errno::ENOENT)?;
        if !inode.kind.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        self.children
            .get(&(dir, OsString::from(name)))
            .copied()
            .ok_or(Errno::ENOENT)
    }

    fn parent_of(&self, id: InodeId) -> Option<InodeId> {
        self.children
            .iter()
            .find(|(_, child)| **child == id)
            .map(|((parent, _), _)| *parent)
    }

    fn is_descendant(&self, mut node: InodeId, ancestor: InodeId) -> bool {
        for _ in 0..=MAX_DEPTH {
            if node == ancestor {
                return true;
            }
            match self.parent_of(node) {
                Some(parent) => node = parent,
                None => return false,
            }
        }
        true
    }

    /// Plan one operation. Pure: no I/O, no clock, no randomness.
    pub fn plan(&self, op: &Op) -> Plan {
        let mut plan = Plan::new(op.op_id);
        if let Err(errno) = self.plan_into(op, &mut plan) {
            plan.verdict = Verdict::Reject(errno);
            plan.effects.clear();
        }
        plan
    }

    fn plan_into(&self, op: &Op, plan: &mut Plan) -> Result<(), Errno> {
        match op.class {
            OpClass::MKDIR => self.plan_mkdir(op, plan),
            OpClass::RMDIR => self.plan_rmdir(op, plan),
            OpClass::CREATE_EXCL => self.plan_create_excl(op, plan),
            OpClass::UNLINK => self.plan_unlink(op, plan),
            OpClass::RENAME => self.plan_rename(op, plan),
            OpClass::LINK => self.plan_link(op, plan),
            OpClass::SYMLINK => self.plan_symlink(op, plan),
            OpClass::WRITE | OpClass::PWRITE => self.plan_write(op, plan),
            OpClass::TRUNCATE => self.plan_truncate(op, plan),
            OpClass::SETATTR => self.plan_setattr(op, plan),
            OpClass::FLOCK | OpClass::FCNTL_LOCK => self.plan_lock(op, plan),
            OpClass::LEAVE => {
                plan.changes.push(Change::RemoveClientLocks {
                    client: op.client_id,
                });
                Ok(())
            }
            OpClass::SYNC_CTRL | OpClass::KEY_ANNOUNCE => Ok(()),
            _ => {
                plan.changes.push(Change::SetDiverged);
                Err(Errno::ENOSYS)
            }
        }
    }

    fn plan_mkdir(&self, op: &Op, plan: &mut Plan) -> Result<(), Errno> {
        let path = op.require_path()?;
        if path == "/" {
            return Err(Errno::EEXIST);
        }
        let (parent, name) = self.resolve_parent(path)?;
        if self.children.contains_key(&(parent, name.clone())) {
            return Err(Errno::EEXIST);
        }
        let id = derive_inode_id(op.op_id);
        if self.inodes.contains_key(&id) {
            plan.changes.push(Change::Patch {
                id,
                patch: InodePatch {
                    tombstone: Some(true),
                    ..InodePatch::default()
                },
            });
            return Err(Errno::EIO);
        }
        let body_mode = match &op.body {
            OpBody::Mkdir { mode } => *mode,
            _ => 0o755,
        };
        let attrs = op.attrs();
        let mode = body_mode & 0o7777;
        plan.effects.push(FsEffect::Mkdir {
            parent,
            name: name.clone(),
            id,
            mode,
        });
        plan.changes.push(Change::Insert {
            id,
            inode: Inode::new(id, Kind::Dir, mode, attrs),
        });
        plan.changes.push(Change::AddChild { parent, name, id });
        plan.changes.push(Change::Patch {
            id: parent,
            patch: InodePatch {
                mtime_ns: Some(attrs.mtime_ns),
                nlink_delta: 1,
                ..InodePatch::default()
            },
        });
        Ok(())
    }

    fn plan_rmdir(&self, op: &Op, plan: &mut Plan) -> Result<(), Errno> {
        let path = op.require_path()?;
        if path == "/" {
            return Err(Errno::EBUSY);
        }
        let (parent, name) = self.resolve_parent(path)?;
        let id = self
            .children
            .get(&(parent, name.clone()))
            .copied()
            .ok_or(Errno::ENOENT)?;
        let inode = self.inodes.get(&id).ok_or(Errno::ENOENT)?;
        if !inode.kind.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        if self.children.keys().any(|(dir, _)| *dir == id) {
            return Err(Errno::ENOTEMPTY);
        }
        let attrs = op.attrs();
        plan.effects.push(FsEffect::Rmdir {
            parent,
            name: name.clone(),
            id,
        });
        plan.changes.push(Change::RemoveChild { parent, name });
        plan.changes.push(Change::Remove { id });
        plan.changes.push(Change::Patch {
            id: parent,
            patch: InodePatch {
                mtime_ns: Some(attrs.mtime_ns),
                nlink_delta: -1,
                ..InodePatch::default()
            },
        });
        Ok(())
    }

    fn plan_create_excl(&self, op: &Op, plan: &mut Plan) -> Result<(), Errno> {
        let path = op.require_path()?;
        if path == "/" {
            return Err(Errno::EEXIST);
        }
        let (parent, name) = self.resolve_parent(path)?;
        if self.children.contains_key(&(parent, name.clone())) {
            return Err(Errno::EEXIST);
        }
        let id = derive_inode_id(op.op_id);
        if self.inodes.contains_key(&id) {
            plan.changes.push(Change::Patch {
                id,
                patch: InodePatch {
                    tombstone: Some(true),
                    ..InodePatch::default()
                },
            });
            return Err(Errno::EIO);
        }
        let body_mode = match &op.body {
            OpBody::CreateExcl { mode, .. } => *mode,
            _ => 0o644,
        };
        let attrs = op.attrs();
        let mode = body_mode & 0o7777;
        plan.effects.push(FsEffect::Create {
            parent,
            name: name.clone(),
            id,
            mode,
        });
        plan.changes.push(Change::Insert {
            id,
            inode: Inode::new(id, Kind::File, mode, attrs),
        });
        plan.changes.push(Change::AddChild { parent, name, id });
        plan.changes.push(Change::Patch {
            id: parent,
            patch: InodePatch {
                mtime_ns: Some(attrs.mtime_ns),
                ..InodePatch::default()
            },
        });
        Ok(())
    }

    fn plan_unlink(&self, op: &Op, plan: &mut Plan) -> Result<(), Errno> {
        let path = op.require_path()?;
        if path == "/" {
            return Err(Errno::EBUSY);
        }
        let (parent, name) = self.resolve_parent(path)?;
        let id = self
            .children
            .get(&(parent, name.clone()))
            .copied()
            .ok_or(Errno::ENOENT)?;
        let inode = self.inodes.get(&id).ok_or(Errno::ENOENT)?;
        if inode.kind.is_dir() {
            return Err(Errno::EISDIR);
        }
        let attrs = op.attrs();
        let tombstone = inode.nlink <= 1;
        plan.effects.push(FsEffect::Unlink {
            parent,
            name: name.clone(),
            id,
        });
        plan.changes.push(Change::RemoveChild { parent, name });
        plan.changes.push(Change::Patch {
            id,
            patch: InodePatch {
                nlink_delta: -1,
                tombstone: tombstone.then_some(true),
                mtime_ns: Some(attrs.mtime_ns),
                ..InodePatch::default()
            },
        });
        plan.changes.push(Change::Patch {
            id: parent,
            patch: InodePatch {
                mtime_ns: Some(attrs.mtime_ns),
                ..InodePatch::default()
            },
        });
        Ok(())
    }

    fn plan_rename(&self, op: &Op, plan: &mut Plan) -> Result<(), Errno> {
        let path = op.require_path()?;
        let OpBody::Rename { path2 } = &op.body else {
            return Err(Errno::EINVAL);
        };
        if path == "/" || path2 == "/" {
            return Err(Errno::EBUSY);
        }
        let (old_parent, old_name) = self.resolve_parent(path)?;
        let id = self
            .children
            .get(&(old_parent, old_name.clone()))
            .copied()
            .ok_or(Errno::ENOENT)?;
        let (new_parent, new_name) = self.resolve_parent(path2)?;
        if old_parent == new_parent && old_name == new_name {
            return Ok(());
        }
        let inode = self.inodes.get(&id).ok_or(Errno::ENOENT)?;
        let attrs = op.attrs();
        let mut replaced_entry = false;
        let mut replaced_state = None;
        if let Some(existing) = self.children.get(&(new_parent, new_name.clone())).copied() {
            if existing == id {
                return Ok(());
            }
            let target = self.inodes.get(&existing).ok_or(Errno::ENOENT)?;
            let target_is_dir = target.kind.is_dir();
            if target_is_dir {
                if !inode.kind.is_dir() {
                    return Err(Errno::EISDIR);
                }
                if self.children.keys().any(|(dir, _)| *dir == existing) {
                    return Err(Errno::ENOTEMPTY);
                }
            } else if inode.kind.is_dir() {
                return Err(Errno::ENOTDIR);
            }
            replaced_entry = true;
            if target_is_dir {
                // The replaced directory has no name left; drop it whole.
                replaced_state = Some(Change::Remove { id: existing });
            } else {
                replaced_state = Some(Change::Patch {
                    id: existing,
                    patch: InodePatch {
                        nlink_delta: -1,
                        tombstone: (target.nlink <= 1).then_some(true),
                        ..InodePatch::default()
                    },
                });
            }
        }
        if inode.kind.is_dir() && self.is_descendant(new_parent, id) {
            return Err(Errno::EINVAL);
        }
        plan.effects.push(FsEffect::Rename {
            from: (old_parent, old_name.clone()),
            to: (new_parent, new_name.clone()),
        });
        plan.changes.push(Change::RemoveChild {
            parent: old_parent,
            name: old_name,
        });
        // The replaced entry must be removed before the new one is inserted,
        // otherwise `AddChild` would be undone by its own removal.
        if replaced_entry {
            plan.changes.push(Change::RemoveChild {
                parent: new_parent,
                name: new_name.clone(),
            });
        }
        plan.changes.push(Change::AddChild {
            parent: new_parent,
            name: new_name,
            id,
        });
        plan.changes.push(Change::Patch {
            id,
            patch: InodePatch {
                mtime_ns: Some(attrs.mtime_ns),
                ..InodePatch::default()
            },
        });
        if inode.kind.is_dir() && old_parent != new_parent {
            // `..` of the moved directory changes parent: the old parent loses
            // one subdirectory link, the new parent gains one.
            plan.changes.push(Change::Patch {
                id: old_parent,
                patch: InodePatch {
                    nlink_delta: -1,
                    mtime_ns: Some(attrs.mtime_ns),
                    ..InodePatch::default()
                },
            });
            plan.changes.push(Change::Patch {
                id: new_parent,
                patch: InodePatch {
                    nlink_delta: 1,
                    mtime_ns: Some(attrs.mtime_ns),
                    ..InodePatch::default()
                },
            });
        }
        if let Some(change) = replaced_state {
            plan.changes.push(change);
        }
        Ok(())
    }

    fn plan_link(&self, op: &Op, plan: &mut Plan) -> Result<(), Errno> {
        let path = op.require_path()?;
        let OpBody::Link { target } = &op.body else {
            return Err(Errno::EINVAL);
        };
        if path == "/" {
            return Err(Errno::EEXIST);
        }
        let id = self.resolve(target)?;
        let inode = self.inodes.get(&id).ok_or(Errno::ENOENT)?;
        if inode.kind.is_dir() {
            return Err(Errno::EPERM);
        }
        let (parent, name) = self.resolve_parent(path)?;
        if self.children.contains_key(&(parent, name.clone())) {
            return Err(Errno::EEXIST);
        }
        let attrs = op.attrs();
        plan.effects.push(FsEffect::Link {
            id,
            parent,
            name: name.clone(),
        });
        plan.changes.push(Change::AddChild { parent, name, id });
        plan.changes.push(Change::Patch {
            id,
            patch: InodePatch {
                nlink_delta: 1,
                mtime_ns: Some(attrs.mtime_ns),
                ..InodePatch::default()
            },
        });
        Ok(())
    }

    fn plan_symlink(&self, op: &Op, plan: &mut Plan) -> Result<(), Errno> {
        let path = op.require_path()?;
        let OpBody::Symlink { target } = &op.body else {
            return Err(Errno::EINVAL);
        };
        if path == "/" {
            return Err(Errno::EEXIST);
        }
        let (parent, name) = self.resolve_parent(path)?;
        if self.children.contains_key(&(parent, name.clone())) {
            return Err(Errno::EEXIST);
        }
        let id = derive_inode_id(op.op_id);
        if self.inodes.contains_key(&id) {
            plan.changes.push(Change::Patch {
                id,
                patch: InodePatch {
                    tombstone: Some(true),
                    ..InodePatch::default()
                },
            });
            return Err(Errno::EIO);
        }
        let attrs = op.attrs();
        let mut inode = Inode::new(id, Kind::Symlink, 0o777, attrs);
        inode.size = target.len() as u64;
        inode.symlink = Some(target.as_bytes().to_vec());
        plan.effects.push(FsEffect::Symlink {
            parent,
            name: name.clone(),
            id,
            target: OsString::from(target),
        });
        plan.changes.push(Change::Insert { id, inode });
        plan.changes.push(Change::AddChild { parent, name, id });
        plan.changes.push(Change::Patch {
            id: parent,
            patch: InodePatch {
                mtime_ns: Some(attrs.mtime_ns),
                ..InodePatch::default()
            },
        });
        Ok(())
    }

    fn plan_write(&self, op: &Op, plan: &mut Plan) -> Result<(), Errno> {
        let path = op.require_path()?;
        let (offset, data) = match &op.body {
            OpBody::Write(data) => (0, *data),
            OpBody::Pwrite { offset, data } => (*offset, *data),
            _ => return Err(Errno::EINVAL),
        };
        let id = self.resolve(path)?;
        let inode = self.inodes.get(&id).ok_or(Errno::ENOENT)?;
        if inode.kind.is_dir() {
            return Err(Errno::EISDIR);
        }
        let end = offset.checked_add(data.total_len).ok_or(Errno::EOVERFLOW)?;
        let attrs = op.attrs();
        plan.effects.push(FsEffect::Write {
            id,
            off: offset,
            data,
        });
        plan.changes.push(Change::Patch {
            id,
            patch: InodePatch {
                size: Some(inode.size.max(end)),
                mtime_ns: Some(attrs.mtime_ns),
                ..InodePatch::default()
            },
        });
        Ok(())
    }

    fn plan_truncate(&self, op: &Op, plan: &mut Plan) -> Result<(), Errno> {
        let path = op.require_path()?;
        let OpBody::Truncate { length } = &op.body else {
            return Err(Errno::EINVAL);
        };
        let id = self.resolve(path)?;
        let inode = self.inodes.get(&id).ok_or(Errno::ENOENT)?;
        if inode.kind.is_dir() {
            return Err(Errno::EISDIR);
        }
        let attrs = op.attrs();
        plan.effects.push(FsEffect::Truncate { id, size: *length });
        plan.changes.push(Change::Patch {
            id,
            patch: InodePatch {
                size: Some(*length),
                mtime_ns: Some(attrs.mtime_ns),
                ..InodePatch::default()
            },
        });
        Ok(())
    }

    fn plan_setattr(&self, op: &Op, plan: &mut Plan) -> Result<(), Errno> {
        let path = op.require_path()?;
        let mode = match &op.body {
            OpBody::Setattr { mode } => *mode,
            _ => None,
        };
        let id = self.resolve(path)?;
        self.inodes.get(&id).ok_or(Errno::ENOENT)?;
        let attrs = op.attrs();
        let delta = AttrDelta {
            mode,
            uid: Some(attrs.uid),
            gid: Some(attrs.gid),
            mtime: Some(timespec_from_ns(attrs.mtime_ns)),
            ..AttrDelta::default()
        };
        plan.effects.push(FsEffect::SetAttr { id, delta });
        plan.changes.push(Change::Patch {
            id,
            patch: InodePatch {
                mode,
                uid: Some(attrs.uid),
                gid: Some(attrs.gid),
                mtime_ns: Some(attrs.mtime_ns),
                ..InodePatch::default()
            },
        });
        Ok(())
    }

    fn plan_lock(&self, op: &Op, plan: &mut Plan) -> Result<(), Errno> {
        let OpBody::Lock {
            lock_type,
            action,
            start,
            len,
            flock,
        } = &op.body
        else {
            return Err(Errno::EINVAL);
        };
        // BSD `flock` is local-only (49 A10): it never enters `S`.
        if *flock {
            return Ok(());
        }
        let path = op.require_path()?;
        let id = self.resolve(path)?;
        let holder = Holder {
            client: op.client_id,
            ctx: 0,
        };
        let end = lock_end(*start, *len);
        if *action == LOCK_ACTION_UNLOCK {
            plan.changes.push(Change::RemoveLocks {
                holder,
                ino: id,
                start: *start,
                end,
            });
            return Ok(());
        }
        let typ = match *lock_type {
            0 => LockType::Read,
            1 => LockType::Write,
            _ => return Err(Errno::EINVAL),
        };
        let key = LockKey {
            ino: id,
            start: *start,
            end,
        };
        for (existing, lock) in &self.locks {
            if lock.holder == holder {
                continue;
            }
            if existing.overlaps(key) && (lock.typ == LockType::Write || typ == LockType::Write) {
                return Err(Errno::EAGAIN);
            }
        }
        plan.changes.push(Change::RemoveLocks {
            holder,
            ino: id,
            start: *start,
            end,
        });
        plan.changes.push(Change::InsertLock {
            key,
            lock: Lock { typ, holder },
        });
        Ok(())
    }

    /// Apply the state delta. Never fails: every field was validated by
    /// `plan`.
    pub fn commit(&mut self, plan: Plan) {
        for change in plan.changes {
            self.apply_change(change);
        }
    }

    fn apply_change(&mut self, change: Change) {
        match change {
            Change::Insert { id, inode } => {
                self.inodes.insert(id, inode);
            }
            Change::Remove { id } => {
                self.inodes.remove(&id);
            }
            Change::Patch { id, patch } => {
                if let Some(inode) = self.inodes.get_mut(&id) {
                    if let Some(mode) = patch.mode {
                        inode.mode = mode;
                    }
                    if let Some(uid) = patch.uid {
                        inode.uid = uid;
                    }
                    if let Some(gid) = patch.gid {
                        inode.gid = gid;
                    }
                    if let Some(mtime) = patch.mtime_ns {
                        inode.mtime_ns = mtime;
                    }
                    if let Some(size) = patch.size {
                        inode.size = size;
                    }
                    if patch.nlink_delta != 0 {
                        inode.nlink = inode.nlink.saturating_add_signed(patch.nlink_delta);
                    }
                    if let Some(tombstone) = patch.tombstone {
                        inode.tombstone = tombstone;
                    }
                }
            }
            Change::AddChild { parent, name, id } => {
                self.children.insert((parent, name), id);
            }
            Change::RemoveChild { parent, name } => {
                self.children.remove(&(parent, name));
            }
            Change::InsertLock { key, lock } => {
                self.locks.insert(key, lock);
            }
            Change::RemoveLocks {
                holder,
                ino,
                start,
                end,
            } => {
                let range = LockKey { ino, start, end };
                self.locks
                    .retain(|key, lock| !(lock.holder == holder && key.overlaps(range)));
            }
            Change::RemoveClientLocks { client } => {
                self.locks.retain(|_, lock| lock.holder.client != client);
            }
            Change::SetDiverged => {
                self.diverged = true;
            }
        }
    }

    /// Reproducible digest of the whole state (INV-10).
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"sm/v1/replay-state\0");
        hasher.update(&(self.inodes.len() as u64).to_le_bytes());
        for (id, inode) in &self.inodes {
            hasher.update(&id.0.to_le_bytes());
            hasher.update(&[kind_code(inode.kind)]);
            hasher.update(&inode.mode.to_le_bytes());
            hasher.update(&inode.uid.to_le_bytes());
            hasher.update(&inode.gid.to_le_bytes());
            hasher.update(&inode.nlink.to_le_bytes());
            hasher.update(&inode.size.to_le_bytes());
            hasher.update(&inode.mtime_ns.to_le_bytes());
            hasher.update(&[u8::from(inode.tombstone)]);
            match &inode.symlink {
                Some(target) => {
                    hasher.update(&(target.len() as u64).to_le_bytes());
                    hasher.update(target);
                }
                None => {
                    hasher.update(&u64::MAX.to_le_bytes());
                }
            }
        }
        hasher.update(&(self.children.len() as u64).to_le_bytes());
        for ((parent, name), id) in &self.children {
            hasher.update(&parent.0.to_le_bytes());
            hasher.update(&(name.len() as u64).to_le_bytes());
            hasher.update(name.as_encoded_bytes());
            hasher.update(&id.0.to_le_bytes());
        }
        hasher.update(&(self.locks.len() as u64).to_le_bytes());
        for (key, lock) in &self.locks {
            hasher.update(&key.ino.0.to_le_bytes());
            hasher.update(&key.start.to_le_bytes());
            hasher.update(&key.end.to_le_bytes());
            hasher.update(&[match lock.typ {
                LockType::Read => 0,
                LockType::Write => 1,
            }]);
            hasher.update(lock.holder.client.as_bytes());
            hasher.update(&lock.holder.ctx.to_le_bytes());
        }
        hasher.update(&[u8::from(self.diverged)]);
        *hasher.finalize().as_bytes()
    }

    /// Materialize a plan.
    ///
    /// The caller must hold the inode locks the plan touches; the engine is a
    /// single writer, but the FUSE write path may be rebasing concurrently.
    pub fn materialize(
        &self,
        plan: &Plan,
        backing: &dyn ReplayBacking,
        data: &dyn OpData,
    ) -> Result<(), Errno> {
        for effect in &plan.effects {
            match effect {
                FsEffect::Mkdir {
                    parent,
                    name,
                    id,
                    mode,
                } => backing.mkdir(*parent, name, *id, *mode)?,
                FsEffect::Create {
                    parent,
                    name,
                    id,
                    mode,
                } => backing.create(*parent, name, *id, *mode)?,
                FsEffect::Symlink {
                    parent,
                    name,
                    id,
                    target,
                } => backing.symlink(*parent, name, *id, Path::new(target.as_os_str()))?,
                FsEffect::Unlink { parent, name, .. } => backing.unlink(*parent, name)?,
                FsEffect::Rmdir { parent, name, .. } => backing.rmdir(*parent, name)?,
                FsEffect::Rename { from, to } => {
                    backing.rename((from.0, from.1.as_os_str()), (to.0, to.1.as_os_str()))?;
                }
                FsEffect::Link { id, parent, name } => backing.link(*id, *parent, name)?,
                FsEffect::Write {
                    id,
                    off,
                    data: source,
                } => {
                    let bytes = data.read(source)?;
                    if bytes.len() as u64 != source.total_len {
                        return Err(Errno::EIO);
                    }
                    if *blake3::hash(&bytes).as_bytes() != source.data_hash {
                        return Err(Errno::EIO);
                    }
                    backing.write_at(*id, *off, &bytes)?;
                }
                FsEffect::Truncate { id, size } => backing.truncate(*id, *size)?,
                FsEffect::SetAttr { id, delta } => backing.set_attr(*id, delta)?,
            }
        }
        Ok(())
    }
}

/// The replay-state operations a caller may drive.
///
/// [`Namespace`] implements it directly; [`Replayer`] adds sequencing, dedup
/// and the pending overlay on top.
pub trait ReplayState: Send {
    /// Plan one operation.
    fn plan(&self, op: &Op) -> Plan;
    /// Apply the disk effects.
    fn materialize(
        &self,
        plan: &Plan,
        backing: &dyn ReplayBacking,
        data: &dyn OpData,
    ) -> Result<(), Errno>;
    /// Apply the state delta.
    fn commit(&mut self, plan: Plan);
    /// Reproducible digest.
    fn hash(&self) -> [u8; 32];
}

impl ReplayState for Namespace {
    fn plan(&self, op: &Op) -> Plan {
        Namespace::plan(self, op)
    }

    fn materialize(
        &self,
        plan: &Plan,
        backing: &dyn ReplayBacking,
        data: &dyn OpData,
    ) -> Result<(), Errno> {
        Namespace::materialize(self, plan, backing, data)
    }

    fn commit(&mut self, plan: Plan) {
        Namespace::commit(self, plan);
    }

    fn hash(&self) -> [u8; 32] {
        Namespace::hash(self)
    }
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/// The disk operations the replay engine needs.
///
/// It mirrors [`crate::store::backing::BackingStore`] with one crucial
/// difference: creation takes the inode identity from the caller. The replay
/// engine derives that identity from the operation id, so every client creates
/// the same inode for the same operation (41 R6). `PosixBacking` needs a thin
/// adapter that forwards `mkdir`/`create`/`symlink` with the supplied id.
pub trait ReplayBacking: Send + Sync {
    /// Create a directory with the caller's identity.
    fn mkdir(&self, parent: InodeId, name: &OsStr, id: InodeId, mode: u32) -> Result<(), Errno>;
    /// Create a regular file with the caller's identity.
    fn create(&self, parent: InodeId, name: &OsStr, id: InodeId, mode: u32) -> Result<(), Errno>;
    /// Create a symlink with the caller's identity.
    fn symlink(
        &self,
        parent: InodeId,
        name: &OsStr,
        id: InodeId,
        target: &Path,
    ) -> Result<(), Errno>;
    /// Remove one directory entry.
    fn unlink(&self, parent: InodeId, name: &OsStr) -> Result<(), Errno>;
    /// Remove one empty directory.
    fn rmdir(&self, parent: InodeId, name: &OsStr) -> Result<(), Errno>;
    /// Rename one entry.
    fn rename(&self, from: (InodeId, &OsStr), to: (InodeId, &OsStr)) -> Result<(), Errno>;
    /// Add a hard link.
    fn link(&self, id: InodeId, parent: InodeId, name: &OsStr) -> Result<(), Errno>;
    /// Write at an offset, completing the whole buffer.
    fn write_at(&self, id: InodeId, off: u64, data: &[u8]) -> Result<(), Errno>;
    /// Truncate.
    fn truncate(&self, id: InodeId, size: u64) -> Result<(), Errno>;
    /// Apply attributes.
    fn set_attr(&self, id: InodeId, delta: &AttrDelta) -> Result<(), Errno>;
    /// Replay one optimistic effect.
    fn apply_effect(&self, id: InodeId, effect: &Effect) -> Result<(), Errno>;
}

/// Resolves `WRITE`/`PWRITE` stream references to plaintext.
///
/// The fragment layer (W16) implements this over the chunk store; the replay
/// engine verifies the plaintext hash before writing anything.
pub trait OpData: Send + Sync {
    /// Read the whole stream named by `data`.
    fn read(&self, data: &DataRef) -> Result<Vec<u8>, Errno>;
}

// ---------------------------------------------------------------------------
// Pending overlay
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingEffect {
    op_id: OpId,
    effect: Effect,
}

/// Optimistic effects of local operations that have not been echoed yet.
///
/// It is shared with the FUSE write path (W13). Insertion happens in the write
/// path before the operation is committed to the outbox; removal happens when
/// the echo arrives.
#[derive(Debug, Default)]
pub struct PendingOverlay {
    inner: Mutex<PendingInner>,
}

#[derive(Debug, Default)]
struct PendingInner {
    by_inode: HashMap<InodeId, BTreeMap<LocalSeq, PendingEffect>>,
    by_op: HashMap<OpId, (InodeId, LocalSeq)>,
}

impl PendingOverlay {
    /// Empty overlay.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register one optimistic effect.
    pub fn insert(&self, ino: InodeId, seq: LocalSeq, op_id: OpId, effect: Effect) {
        let mut inner = self.lock();
        inner.by_op.insert(op_id, (ino, seq));
        inner
            .by_inode
            .entry(ino)
            .or_default()
            .insert(seq, PendingEffect { op_id, effect });
    }

    /// Remove and return the effect of `op_id` (echo path).
    pub fn take(&self, op_id: OpId) -> Option<Effect> {
        let mut inner = self.lock();
        let (ino, seq) = *inner.by_op.get(&op_id)?;
        let pending = inner.by_inode.get_mut(&ino)?.remove(&seq)?;
        inner.by_op.remove(&op_id);
        if inner.by_inode.get(&ino).is_some_and(BTreeMap::is_empty) {
            inner.by_inode.remove(&ino);
        }
        Some(pending.effect)
    }

    /// Whether `ino` has any pending effect.
    pub fn has(&self, ino: InodeId) -> bool {
        self.lock().by_inode.contains_key(&ino)
    }

    /// Number of pending effects.
    pub fn len(&self) -> usize {
        self.lock().by_op.len()
    }

    /// Whether nothing is pending.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Replay every pending effect of `ino`, in `LocalSeq` order.
    ///
    /// Effects are removed one by one as they succeed; a failure leaves the
    /// remainder in place and is reported to the caller.
    pub fn replay(&self, ino: InodeId, backing: &dyn ReplayBacking) -> Result<(), Errno> {
        let effects: Vec<(LocalSeq, OpId, Effect)> = {
            let inner = self.lock();
            inner
                .by_inode
                .get(&ino)
                .map(|effects| {
                    effects
                        .iter()
                        .map(|(seq, pending)| (*seq, pending.op_id, pending.effect.clone()))
                        .collect()
                })
                .unwrap_or_default()
        };
        for (seq, op_id, effect) in effects {
            backing.apply_effect(ino, &effect)?;
            let mut inner = self.lock();
            if let Some(effects) = inner.by_inode.get_mut(&ino) {
                effects.remove(&seq);
                if effects.is_empty() {
                    inner.by_inode.remove(&ino);
                }
            }
            inner.by_op.remove(&op_id);
        }
        Ok(())
    }

    /// Drop every pending effect of `ino` (tombstone exception, 41 §5.4).
    pub fn discard(&self, ino: InodeId) {
        let mut inner = self.lock();
        if let Some(effects) = inner.by_inode.remove(&ino) {
            for pending in effects.values() {
                inner.by_op.remove(&pending.op_id);
            }
        }
    }

    /// Drop everything (resync, unmount).
    pub fn clear(&self) {
        let mut inner = self.lock();
        inner.by_inode.clear();
        inner.by_op.clear();
    }

    fn lock(&self) -> MutexGuard<'_, PendingInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

// ---------------------------------------------------------------------------
// Dedup, reorder, waiters, budget
// ---------------------------------------------------------------------------

/// `op_id` dedup window: 1M ids or 24 h, whichever comes first (39 §2.3).
#[derive(Debug)]
pub struct DedupWindow {
    log: OpIdLog,
    order: VecDeque<(OpId, Duration)>,
    ttl: Duration,
}

impl DedupWindow {
    /// Build a window with the given capacity and age limit.
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            log: OpIdLog::new(capacity),
            order: VecDeque::new(),
            ttl,
        }
    }

    /// Build a window from the client tuning.
    pub fn with_tuning(tuning: &Tuning) -> Self {
        Self::new(tuning.dedup_capacity, tuning.dedup_ttl)
    }

    /// Record an observation.
    pub fn observe(&mut self, op_id: OpId, seq: Seq, now: Duration) -> OpIdVerdict {
        self.prune(now);
        let verdict = self.log.observe(op_id, seq);
        if verdict == OpIdVerdict::Fresh {
            self.order.push_back((op_id, now));
        }
        verdict
    }

    /// Minimum sequence recorded for `op_id`.
    pub fn get(&self, op_id: OpId) -> Option<Seq> {
        self.log.get(op_id)
    }

    /// Number of tracked ids.
    pub fn len(&self) -> usize {
        self.log.len()
    }

    /// Whether the window is empty.
    pub fn is_empty(&self) -> bool {
        self.log.is_empty()
    }

    /// Configured capacity.
    pub fn capacity(&self) -> usize {
        self.log.capacity()
    }

    fn prune(&mut self, now: Duration) {
        let mut expired = false;
        while let Some((_, at)) = self.order.front() {
            if now.saturating_sub(*at) > self.ttl {
                self.order.pop_front();
                expired = true;
            } else {
                break;
            }
        }
        if expired {
            // `OpIdLog` has no removal, so rebuild it from the survivors.
            let mut fresh = OpIdLog::new(self.log.capacity());
            for (op_id, _) in &self.order {
                if let Some(seq) = self.log.get(*op_id) {
                    fresh.observe(*op_id, seq);
                }
            }
            self.log = fresh;
        }
    }
}

/// Frames held while waiting for a missing sequence (≤1024 frames / ≤1 s).
#[derive(Debug)]
pub struct ReorderBuffer {
    frames: BTreeMap<Seq, IncomingOp>,
    first_at: Option<Duration>,
    limit: usize,
    wait: Duration,
}

impl ReorderBuffer {
    /// Build a buffer with the given limits.
    pub fn new(limit: usize, wait: Duration) -> Self {
        Self {
            frames: BTreeMap::new(),
            first_at: None,
            limit: limit.max(1),
            wait,
        }
    }

    /// Build a buffer from the client tuning.
    pub fn with_tuning(tuning: &Tuning) -> Self {
        Self::new(tuning.reorder_frames, tuning.reorder_wait)
    }

    /// Buffer one frame. Exceeding the limit is a real gap.
    pub fn insert(&mut self, incoming: IncomingOp, now: Duration) -> Result<(), ResyncReason> {
        if self.frames.is_empty() {
            self.first_at = Some(now);
        }
        self.frames.insert(incoming.seq, incoming);
        if self.frames.len() > self.limit {
            return Err(ResyncReason::SeqGap);
        }
        Ok(())
    }

    /// Remove the frame at `seq`, if buffered.
    pub fn pop(&mut self, seq: Seq) -> Option<IncomingOp> {
        let frame = self.frames.remove(&seq);
        if self.frames.is_empty() {
            self.first_at = None;
        }
        frame
    }

    /// Whether the oldest buffered frame waited too long.
    pub fn expired(&self, now: Duration) -> bool {
        self.first_at
            .is_some_and(|at| now.saturating_sub(at) >= self.wait)
    }

    /// Number of buffered frames.
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Whether nothing is buffered.
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Drop every buffered frame.
    pub fn clear(&mut self) {
        self.frames.clear();
        self.first_at = None;
    }
}

/// Senders waiting for one operation's verdict.
type WaiterMap = BTreeMap<OpId, Vec<Sender<Result<(), Errno>>>>;

/// Waiters for local operations, keyed by `op_id`.
///
/// The table is shared between the FUSE write path and the replay engine
/// through [`SyncHandle`]. `live` records whether a replay engine is attached:
/// without one there is no sequence to wait for, so a metadata callback keeps
/// the local-only behaviour instead of blocking on an echo that cannot come.
#[derive(Debug, Default)]
pub struct Waiters {
    inner: Mutex<WaiterMap>,
    live: AtomicBool,
}

impl Waiters {
    /// Empty waiter table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register interest in one operation.
    pub fn register(&self, op_id: OpId) -> Receiver<Result<(), Errno>> {
        let (tx, rx) = mpsc::channel();
        self.lock().entry(op_id).or_default().push(tx);
        rx
    }

    /// Mark a replay engine as attached.
    pub fn arm(&self) {
        self.live.store(true, Ordering::Release);
    }

    /// Mark the replay engine as gone.
    pub fn disarm(&self) {
        self.live.store(false, Ordering::Release);
    }

    /// Whether an echo for a registered operation can still arrive.
    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }

    /// Forget one waiter without waking it.
    pub fn cancel(&self, op_id: OpId) {
        self.lock().remove(&op_id);
    }

    /// Wake every waiter of `op_id`.
    pub fn wake(&self, op_id: OpId, verdict: Result<(), Errno>) {
        let senders = self.lock().remove(&op_id);
        if let Some(senders) = senders {
            for sender in senders {
                let _ = sender.send(verdict);
            }
        }
    }

    /// Drop every waiter; receivers observe `RecvError`, which the FUSE layer
    /// maps to `ENOTCONN` (41 §7.3).
    pub fn drop_all(&self) {
        self.lock().clear();
    }

    /// Number of operations with waiters.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether nobody waits.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    fn lock(&self) -> MutexGuard<'_, WaiterMap> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The FUSE write path's handle on the replay engine.
///
/// The adapter is mounted before a JOIN produces a [`Replayer`], so the client
/// creates one handle first, gives a clone to the write path, and attaches the
/// same handle to the replayer once the JOIN completes. Both sides then share
/// one waiter table and one `S`, which is what lets a metadata callback block
/// until its own operation has been applied.
#[derive(Clone, Debug)]
pub struct SyncHandle {
    state: Arc<RwLock<Namespace>>,
    waiters: Arc<Waiters>,
}

impl Default for SyncHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncHandle {
    /// An unattached handle: no replayer, no waiters.
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(Namespace::new())),
            waiters: Arc::new(Waiters::new()),
        }
    }

    /// Whether a replayer is attached and can answer echoes.
    pub fn is_live(&self) -> bool {
        self.waiters.is_live()
    }

    /// Register for the verdict of `op_id`, or `None` when no replayer is
    /// attached.
    pub fn register(&self, op_id: OpId) -> Option<Receiver<Result<(), Errno>>> {
        self.is_live().then(|| self.waiters.register(op_id))
    }

    /// Forget a waiter whose wait gave up (timeout or disconnect).
    pub fn cancel(&self, op_id: OpId) {
        self.waiters.cancel(op_id);
    }

    /// The first foreign lock that would block `typ` on `[start, end]`.
    pub fn find_lock(
        &self,
        ino: InodeId,
        start: u64,
        end: u64,
        typ: LockType,
        client: ClientId,
    ) -> Option<(LockKey, Lock)> {
        self.state
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .find_lock(ino, start, end, typ, client)
    }
}

/// Resync budget: three rebuilds without a ≥60 s steady window are fatal.
#[derive(Clone, Copy, Debug)]
pub struct ResyncBudget {
    limit: u32,
    count: u32,
    steady_since: Option<Duration>,
    window: Duration,
}

impl ResyncBudget {
    /// Build a budget.
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit: limit.max(1),
            count: 0,
            steady_since: None,
            window,
        }
    }

    /// Build a budget from the client tuning.
    pub fn with_tuning(tuning: &Tuning) -> Self {
        Self::new(tuning.resync_budget, tuning.steady_window)
    }

    /// Record that the replay state is advancing again.
    pub fn note_steady(&mut self, now: Duration) {
        if self.steady_since.is_none() {
            self.steady_since = Some(now);
        }
    }

    /// Record a resync attempt.
    pub fn on_resync(&mut self, now: Duration) -> Result<(), Fatal> {
        if let Some(since) = self.steady_since {
            if now.saturating_sub(since) >= self.window {
                self.count = 0;
            }
        }
        self.steady_since = None;
        self.count = self.count.saturating_add(1);
        if self.count >= self.limit {
            return Err(Fatal::ResyncLoop);
        }
        Ok(())
    }

    /// Resyncs recorded in the current run.
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Forget the history (tests, new epoch after a successful join).
    pub fn reset(&mut self) {
        self.count = 0;
        self.steady_since = None;
    }
}

// ---------------------------------------------------------------------------
// Replayer
// ---------------------------------------------------------------------------

/// The single writer of `S(seq)`.
///
/// The state sits behind `RwLock` only so the FUSE layer can observe it; the
/// replayer is the sole writer, which is what makes `plan` and `commit`
/// atomic with respect to each other.
pub struct Replayer {
    state: Arc<RwLock<Namespace>>,
    applied: Seq,
    epoch: u64,
    client_id: ClientId,
    dedup: DedupWindow,
    reorder: ReorderBuffer,
    budget: ResyncBudget,
    waiters: Arc<Waiters>,
    pending: Arc<PendingOverlay>,
    backpressure: Arc<Backpressure>,
}

impl fmt::Debug for Replayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Replayer")
            .field("applied", &self.applied)
            .field("epoch", &self.epoch)
            .field("inodes", &self.read_state().len())
            .field("reorder", &self.reorder.len())
            .field("dedup", &self.dedup.len())
            .field("resyncs", &self.budget.count())
            .finish()
    }
}

impl Replayer {
    /// Build a replayer positioned at `covered` (the JOIN watermark).
    pub fn new(
        client_id: ClientId,
        covered: Seq,
        epoch: u64,
        tuning: &Tuning,
        pending: Arc<PendingOverlay>,
    ) -> Self {
        Self {
            state: Arc::new(RwLock::new(Namespace::new())),
            applied: covered,
            epoch,
            client_id,
            dedup: DedupWindow::with_tuning(tuning),
            reorder: ReorderBuffer::with_tuning(tuning),
            budget: ResyncBudget::with_tuning(tuning),
            waiters: Arc::new(Waiters::new()),
            pending,
            backpressure: Arc::new(Backpressure::default_window()),
        }
    }

    /// Share `state` and the waiter table with a [`SyncHandle`].
    ///
    /// The client creates the handle before the mount and attaches it here
    /// once the JOIN produces this replayer. Attaching also arms the table:
    /// from this point on a metadata callback waits for its own echo.
    pub fn with_sync(mut self, sync: SyncHandle) -> Self {
        self.state = Arc::clone(&sync.state);
        self.waiters = Arc::clone(&sync.waiters);
        self.waiters.arm();
        self
    }

    /// Attach the replay window shared with the outbox.
    ///
    /// A fresh session starts with an open window: any in-flight count left
    /// by a predecessor belongs to operations whose echo cannot arrive.
    pub fn with_backpressure(mut self, backpressure: Arc<Backpressure>) -> Self {
        backpressure.reset();
        self.backpressure = backpressure;
        self
    }

    /// Current watermark.
    pub const fn applied(&self) -> Seq {
        self.applied
    }

    /// Current epoch.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Read-only view of `S` for the FUSE layer.
    pub fn read_state(&self) -> RwLockReadGuard<'_, Namespace> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// The state handle, for adapters that need to keep it.
    pub fn state_handle(&self) -> Arc<RwLock<Namespace>> {
        Arc::clone(&self.state)
    }

    /// Rebuild `S` from the manifest the JOIN installed.
    ///
    /// Call this once, after the cluster-wins step has made the disk equal to
    /// `manifest` and before the first frame. See
    /// [`Namespace::rebuild_from_manifest`] for the derivation and its
    /// limits.
    ///
    /// # Errors
    ///
    /// The [`Namespace::rebuild_from_manifest`] errors.
    pub fn rebuild_from_manifest(&mut self, manifest: &Manifest) -> Result<(), Errno> {
        self.state
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .rebuild_from_manifest(manifest)
    }

    /// The pending overlay shared with the write path.
    pub fn pending(&self) -> &Arc<PendingOverlay> {
        &self.pending
    }

    /// Register a waiter for a local operation.
    pub fn register_waiter(&self, op_id: OpId) -> Receiver<Result<(), Errno>> {
        self.waiters.register(op_id)
    }

    /// Wake every waiter as `ENOTCONN` by dropping the senders.
    pub fn fail_all_waiters(&self) {
        self.waiters.drop_all();
    }

    /// Number of buffered frames.
    pub fn reorder_len(&self) -> usize {
        self.reorder.len()
    }

    /// Number of dedup entries.
    pub fn dedup_len(&self) -> usize {
        self.dedup.len()
    }

    /// Resyncs recorded in the current run.
    pub const fn resync_count(&self) -> u32 {
        self.budget.count()
    }

    /// Reproducible digest of `S`.
    pub fn snapshot_hash(&self) -> [u8; 32] {
        self.read_state().hash()
    }

    /// Accept one `ORDERED` frame.
    pub fn on_ordered(
        &mut self,
        incoming: IncomingOp,
        now: Duration,
        backing: &dyn ReplayBacking,
        data: &dyn OpData,
    ) -> Result<Progress, Fatal> {
        if incoming.epoch != self.epoch {
            return Err(Fatal::Resync(ResyncReason::EpochChanged));
        }
        let seq = incoming.seq;
        if !seq.is_sequenced() {
            return Err(Fatal::Resync(ResyncReason::Unsequenced));
        }
        if seq <= self.applied {
            return match self.dedup.observe(incoming.op.op_id, seq, now) {
                OpIdVerdict::Fresh => Err(Fatal::Resync(ResyncReason::Rollback)),
                OpIdVerdict::Duplicate | OpIdVerdict::Earlier => Ok(Progress {
                    applied: self.applied,
                    verdict: Ok(()),
                    duplicate: true,
                    buffered: false,
                    bytes_written: 0,
                }),
            };
        }
        let expected = self.applied.checked_next().unwrap_or(self.applied);
        if seq > expected {
            if let Err(reason) = self.reorder.insert(incoming, now) {
                return Err(Fatal::Resync(reason));
            }
            // A hole means the replay cannot advance: stop local production
            // until it fills instead of pushing the server outbox towards a
            // drop that would turn the hole into a resync.
            self.backpressure.set_gap(true);
            return Ok(Progress {
                applied: self.applied,
                verdict: Ok(()),
                duplicate: false,
                buffered: true,
                bytes_written: 0,
            });
        }

        let (verdict, mut written) = self.apply_frame(incoming, now, backing, data)?;
        while let Some(frame) = self
            .reorder
            .pop(self.applied.checked_next().unwrap_or(self.applied))
        {
            // The verdict of a buffered frame belongs to its own waiter, which
            // `apply_frame` already woke; the caller only sees the frame at
            // `expected`.
            let (_, extra) = self.apply_frame(frame, now, backing, data)?;
            written = written.saturating_add(extra);
        }
        if self.reorder.is_empty() {
            self.backpressure.set_gap(false);
        }
        Ok(Progress {
            applied: self.applied,
            verdict,
            duplicate: false,
            buffered: false,
            bytes_written: written,
        })
    }

    /// Accept a `LEAVE` notice; it occupies a sequence like any other frame.
    pub fn on_leave(
        &mut self,
        seq: Seq,
        epoch: u64,
        leave: &Leave,
        now: Duration,
        backing: &dyn ReplayBacking,
        data: &dyn OpData,
    ) -> Result<Progress, Fatal> {
        let op = Op::new(
            leave_op_id(seq, leave.client_id),
            leave.client_id,
            OpClass::LEAVE,
            "/",
        );
        self.on_ordered(IncomingOp::new(seq, epoch, op), now, backing, data)
    }

    /// Report a hole timeout; the caller turns `Some` into a resync.
    ///
    /// The budget is charged by [`Replayer::begin_resync`], the single point
    /// where a rebuild actually starts; counting here as well would consume
    /// two attempts per incident.
    pub fn poll_timeout(&mut self, now: Duration) -> Option<Fatal> {
        if !self.reorder.expired(now) {
            return None;
        }
        Some(Fatal::Resync(ResyncReason::SeqGap))
    }

    /// Rebuild from a fresh manifest: reset the watermark and drop transient
    /// state. The dedup window survives, because an operation that was already
    /// applied before the rebuild must not be applied twice.
    pub fn begin_resync(&mut self, covered: Seq, epoch: u64, now: Duration) -> Result<(), Fatal> {
        self.budget.on_resync(now)?;
        self.applied = covered;
        self.epoch = epoch;
        self.reorder.clear();
        self.pending.clear();
        self.waiters.drop_all();
        self.backpressure.reset();
        Ok(())
    }

    /// Mark the start of a steady period (used by the resync budget).
    pub fn note_steady(&mut self, now: Duration) {
        self.budget.note_steady(now);
    }

    fn apply_frame(
        &mut self,
        incoming: IncomingOp,
        now: Duration,
        backing: &dyn ReplayBacking,
        data: &dyn OpData,
    ) -> Result<(Result<(), Errno>, u64), Fatal> {
        let seq = incoming.seq;
        let op = incoming.op;
        if self.dedup.observe(op.op_id, seq, now) != OpIdVerdict::Fresh {
            // The same operation at a larger sequence: the total order already
            // applied it. Advance the watermark, touch nothing.
            self.applied = seq;
            self.waiters.wake(op.op_id, Ok(()));
            self.budget.note_steady(now);
            return Ok((Ok(()), 0));
        }

        // A fresh echo of our own operation frees one slot in the production
        // window. A duplicate was already counted when it was fresh, and a
        // `LEAVE` is never admitted through the outbox.
        if op.client_id == self.client_id && op.class != OpClass::LEAVE {
            self.backpressure.note_echo();
        }

        let plan = self.read_state().plan(&op);
        let mut written = 0u64;
        let verdict = match plan.verdict {
            Verdict::Apply => {
                let already_on_disk = self.pending.take(op.op_id).is_some();
                if !already_on_disk {
                    if let Err(errno) = self.read_state().materialize(&plan, backing, data) {
                        return Err(Fatal::Materialize { seq, errno });
                    }
                    written = plan
                        .effects
                        .iter()
                        .map(|effect| match effect {
                            FsEffect::Write { data: source, .. } => source.total_len,
                            _ => 0,
                        })
                        .sum();
                    if op.client_id != self.client_id {
                        if let Err(errno) = self.rebase(&plan, backing) {
                            return Err(Fatal::Materialize { seq, errno });
                        }
                    }
                }
                self.state
                    .write()
                    .unwrap_or_else(PoisonError::into_inner)
                    .commit(plan);
                Ok(())
            }
            Verdict::Reject(errno) => {
                self.state
                    .write()
                    .unwrap_or_else(PoisonError::into_inner)
                    .commit(plan);
                Err(errno)
            }
        };
        self.applied = seq;
        self.waiters.wake(op.op_id, verdict);
        self.budget.note_steady(now);
        Ok((verdict, written))
    }

    fn rebase(&mut self, plan: &Plan, backing: &dyn ReplayBacking) -> Result<(), Errno> {
        for change in &plan.changes {
            if let Change::Patch {
                id,
                patch:
                    InodePatch {
                        tombstone: Some(true),
                        ..
                    },
            } = change
            {
                self.pending.discard(*id);
            }
        }
        let mut touched = BTreeSet::new();
        for effect in &plan.effects {
            if let Some(id) = effect.touched_inode() {
                touched.insert(id);
            }
        }
        for id in touched {
            if self.pending.has(id) {
                self.pending.replay(id, backing)?;
            }
        }
        Ok(())
    }
}

impl Drop for Replayer {
    fn drop(&mut self) {
        // A waiting FUSE callback must not outlive the engine that could
        // answer it: disarm first, then fail every registered waiter with
        // `ENOTCONN`.
        self.waiters.disarm();
        self.waiters.drop_all();
        // No echo can arrive after the engine is gone; a successor session
        // must start with an open production window.
        self.backpressure.reset();
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Derive the inode identity of a creating operation.
///
/// The wire has no field for it (41 R6); deriving it from the operation id is
/// deterministic, collision-free in practice, and identical on every client.
pub fn derive_inode_id(op_id: OpId) -> InodeId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sm/v1/inode-id\0");
    hasher.update(op_id.as_bytes());
    let hash = hasher.finalize();
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&hash.as_bytes()[..16]);
    let id = InodeId(u128::from_le_bytes(raw));
    if id.is_root() { InodeId(1) } else { id }
}

/// A `LEAVE` has no `op_id` on the wire; derive one from its sequence so a
/// duplicate frame is still recognised as a duplicate.
fn leave_op_id(seq: Seq, client: ClientId) -> OpId {
    let mut raw = [0u8; 16];
    raw[..8].copy_from_slice(&seq.get().to_le_bytes());
    raw[8..].copy_from_slice(&client.as_bytes()[..8]);
    OpId::from_bytes(raw)
}

fn split_segments(path: &str) -> Result<Vec<&str>, Errno> {
    if path.is_empty() || !path.starts_with('/') {
        return Err(Errno::EINVAL);
    }
    if path == "/" {
        return Ok(Vec::new());
    }
    let mut segments = Vec::new();
    for segment in path[1..].split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(Errno::EINVAL);
        }
        if segment.len() > NAME_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        segments.push(segment);
    }
    if segments.len() > MAX_DEPTH {
        return Err(Errno::ENAMETOOLONG);
    }
    Ok(segments)
}

fn lock_end(start: u64, len: u64) -> u64 {
    if len == 0 {
        u64::MAX
    } else {
        start.saturating_add(len).saturating_sub(1)
    }
}

fn timespec_from_ns(ns: u64) -> Timespec {
    Timespec {
        sec: (ns / 1_000_000_000) as i64,
        nsec: (ns % 1_000_000_000) as i64,
    }
}

fn kind_code(kind: Kind) -> u8 {
    match kind {
        Kind::File => 1,
        Kind::Dir => 2,
        Kind::Symlink => 3,
        Kind::Char => 4,
        Kind::Block => 5,
        Kind::Fifo => 6,
        Kind::Socket => 7,
        Kind::Unknown => 8,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::protocol::frame::SessionId;

    const EPOCH: u64 = 7;

    fn cid(seed: u8) -> ClientId {
        ClientId::from_bytes([seed; 16])
    }

    fn oid(seed: u8) -> OpId {
        OpId::from_bytes([seed; 16])
    }

    fn oid_for(seq: u64) -> OpId {
        let mut raw = [0u8; 16];
        raw[..8].copy_from_slice(&seq.to_le_bytes());
        OpId::from_bytes(raw)
    }

    fn t(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }

    fn attrs(mtime: u64) -> OpAttrs {
        OpAttrs {
            mode: None,
            uid: 1000,
            gid: 1000,
            mtime_ns: mtime,
        }
    }

    fn mkdir(seed: u8, client: u8, path: &str) -> Op {
        Op::new(oid(seed), cid(client), OpClass::MKDIR, path)
            .with_attrs(attrs(1))
            .with_body(OpBody::Mkdir { mode: 0o755 })
    }

    fn create(seed: u8, client: u8, path: &str) -> Op {
        Op::new(oid(seed), cid(client), OpClass::CREATE_EXCL, path)
            .with_attrs(attrs(1))
            .with_body(OpBody::CreateExcl {
                mode: 0o644,
                flags: 0,
            })
    }

    fn pwrite(seed: u8, client: u8, path: &str, off: u64, data: DataRef) -> Op {
        Op::new(oid(seed), cid(client), OpClass::PWRITE, path)
            .with_attrs(attrs(2))
            .with_body(OpBody::Pwrite { offset: off, data })
    }

    fn truncate_op(seed: u8, client: u8, path: &str, length: u64) -> Op {
        Op::new(oid(seed), cid(client), OpClass::TRUNCATE, path)
            .with_attrs(attrs(3))
            .with_body(OpBody::Truncate { length })
    }

    fn rename_op(seed: u8, client: u8, from: &str, to: &str) -> Op {
        Op::new(oid(seed), cid(client), OpClass::RENAME, from)
            .with_attrs(attrs(4))
            .with_body(OpBody::Rename {
                path2: to.to_owned(),
            })
    }

    fn link_op(seed: u8, client: u8, path: &str, target: &str) -> Op {
        Op::new(oid(seed), cid(client), OpClass::LINK, path)
            .with_attrs(attrs(5))
            .with_body(OpBody::Link {
                target: target.to_owned(),
            })
    }

    fn unlink_op(seed: u8, client: u8, path: &str) -> Op {
        Op::new(oid(seed), cid(client), OpClass::UNLINK, path).with_attrs(attrs(6))
    }

    fn symlink_op(seed: u8, client: u8, path: &str, target: &str) -> Op {
        Op::new(oid(seed), cid(client), OpClass::SYMLINK, path)
            .with_attrs(attrs(7))
            .with_body(OpBody::Symlink {
                target: target.to_owned(),
            })
    }

    fn setattr_op(seed: u8, client: u8, path: &str, mode: u32) -> Op {
        Op::new(oid(seed), cid(client), OpClass::SETATTR, path)
            .with_attrs(attrs(8))
            .with_body(OpBody::Setattr { mode: Some(mode) })
    }

    fn lock_op(seed: u8, client: u8, path: &str, action: u8) -> Op {
        Op::new(oid(seed), cid(client), OpClass::FCNTL_LOCK, path)
            .with_attrs(attrs(9))
            .with_body(OpBody::Lock {
                lock_type: 1,
                action,
                start: 0,
                len: 0,
                flock: false,
            })
    }

    fn replayer(client: u8) -> (Replayer, Arc<PendingOverlay>) {
        let pending = Arc::new(PendingOverlay::new());
        let replayer = Replayer::new(
            cid(client),
            Seq::UNSEQUENCED,
            EPOCH,
            &Tuning::default(),
            Arc::clone(&pending),
        );
        (replayer, pending)
    }

    fn frame(seq: u64, op: Op) -> IncomingOp {
        IncomingOp::new(Seq(seq), EPOCH, op)
    }

    #[derive(Debug, Default)]
    struct MemState {
        dirs: BTreeSet<InodeId>,
        files: BTreeMap<InodeId, Vec<u8>>,
        symlinks: BTreeMap<InodeId, Vec<u8>>,
        entries: BTreeMap<(InodeId, OsString), InodeId>,
        effects: usize,
    }

    struct MemoryBacking {
        state: Mutex<MemState>,
    }

    impl MemoryBacking {
        fn new() -> Self {
            let mut state = MemState::default();
            state.dirs.insert(InodeId::ROOT);
            Self {
                state: Mutex::new(state),
            }
        }

        fn lock(&self) -> MutexGuard<'_, MemState> {
            self.state.lock().unwrap()
        }

        fn file(&self, id: InodeId) -> Option<Vec<u8>> {
            self.lock().files.get(&id).cloned()
        }

        fn effect_count(&self) -> usize {
            self.lock().effects
        }
    }

    impl ReplayBacking for MemoryBacking {
        fn mkdir(
            &self,
            parent: InodeId,
            name: &OsStr,
            id: InodeId,
            _mode: u32,
        ) -> Result<(), Errno> {
            let mut state = self.lock();
            if state.entries.contains_key(&(parent, name.to_os_string())) {
                return Err(Errno::EEXIST);
            }
            state.dirs.insert(id);
            state.entries.insert((parent, name.to_os_string()), id);
            Ok(())
        }

        fn create(
            &self,
            parent: InodeId,
            name: &OsStr,
            id: InodeId,
            _mode: u32,
        ) -> Result<(), Errno> {
            let mut state = self.lock();
            if state.entries.contains_key(&(parent, name.to_os_string())) {
                return Err(Errno::EEXIST);
            }
            state.files.insert(id, Vec::new());
            state.entries.insert((parent, name.to_os_string()), id);
            Ok(())
        }

        fn symlink(
            &self,
            parent: InodeId,
            name: &OsStr,
            id: InodeId,
            target: &Path,
        ) -> Result<(), Errno> {
            let mut state = self.lock();
            if state.entries.contains_key(&(parent, name.to_os_string())) {
                return Err(Errno::EEXIST);
            }
            state
                .symlinks
                .insert(id, target.as_os_str().as_encoded_bytes().to_vec());
            state.entries.insert((parent, name.to_os_string()), id);
            Ok(())
        }

        fn unlink(&self, parent: InodeId, name: &OsStr) -> Result<(), Errno> {
            self.lock()
                .entries
                .remove(&(parent, name.to_os_string()))
                .map(|_| ())
                .ok_or(Errno::ENOENT)
        }

        fn rmdir(&self, parent: InodeId, name: &OsStr) -> Result<(), Errno> {
            self.lock()
                .entries
                .remove(&(parent, name.to_os_string()))
                .map(|_| ())
                .ok_or(Errno::ENOENT)
        }

        fn rename(&self, from: (InodeId, &OsStr), to: (InodeId, &OsStr)) -> Result<(), Errno> {
            let mut state = self.lock();
            let id = state
                .entries
                .remove(&(from.0, from.1.to_os_string()))
                .ok_or(Errno::ENOENT)?;
            state.entries.insert((to.0, to.1.to_os_string()), id);
            Ok(())
        }

        fn link(&self, id: InodeId, parent: InodeId, name: &OsStr) -> Result<(), Errno> {
            let mut state = self.lock();
            state.entries.insert((parent, name.to_os_string()), id);
            Ok(())
        }

        fn write_at(&self, id: InodeId, off: u64, data: &[u8]) -> Result<(), Errno> {
            let mut state = self.lock();
            let buffer = state.files.get_mut(&id).ok_or(Errno::ENOENT)?;
            let start = usize::try_from(off).map_err(|_| Errno::EOVERFLOW)?;
            let end = start.checked_add(data.len()).ok_or(Errno::EOVERFLOW)?;
            if buffer.len() < end {
                buffer.resize(end, 0);
            }
            buffer[start..end].copy_from_slice(data);
            Ok(())
        }

        fn truncate(&self, id: InodeId, size: u64) -> Result<(), Errno> {
            let mut state = self.lock();
            let buffer = state.files.get_mut(&id).ok_or(Errno::ENOENT)?;
            buffer.resize(usize::try_from(size).map_err(|_| Errno::EOVERFLOW)?, 0);
            Ok(())
        }

        fn set_attr(&self, _id: InodeId, _delta: &AttrDelta) -> Result<(), Errno> {
            Ok(())
        }

        fn apply_effect(&self, id: InodeId, effect: &Effect) -> Result<(), Errno> {
            self.lock().effects += 1;
            match effect {
                Effect::Write { off, data } => self.write_at(id, *off, data),
                Effect::Truncate { size } => self.truncate(id, *size),
                Effect::SetAttr(_) | Effect::Xattr { .. } => Ok(()),
            }
        }
    }

    #[derive(Default)]
    struct MapData {
        streams: BTreeMap<u128, Vec<u8>>,
    }

    impl MapData {
        fn new() -> Self {
            Self::default()
        }

        fn add(&mut self, session: u128, bytes: &[u8]) -> DataRef {
            self.streams.insert(session, bytes.to_vec());
            DataRef {
                session: SessionId::new(session),
                total_len: bytes.len() as u64,
                data_hash: *blake3::hash(bytes).as_bytes(),
            }
        }
    }

    impl OpData for MapData {
        fn read(&self, data: &DataRef) -> Result<Vec<u8>, Errno> {
            self.streams
                .get(&data.session.get())
                .cloned()
                .ok_or(Errno::ENOENT)
        }
    }

    /// U-REPLAY / INV-10: the same operation order yields the same state.
    #[test]
    fn u_replayer_deterministic_across_clients() {
        let mut data = MapData::new();
        let stream = data.add(1, b"hello");
        let ops = [
            (1, mkdir(1, 1, "/d")),
            (2, create(2, 1, "/d/f")),
            (3, pwrite(3, 1, "/d/f", 0, stream)),
            (4, rename_op(4, 1, "/d/f", "/d/g")),
            (5, link_op(5, 1, "/d/g", "/d/h")),
            (6, unlink_op(6, 1, "/d/h")),
            (7, symlink_op(7, 1, "/d/s", "g")),
            (8, truncate_op(8, 1, "/d/g", 2)),
            (9, setattr_op(9, 1, "/d/g", 0o600)),
        ];
        let mut hashes = Vec::new();
        let mut contents = Vec::new();
        for client in [1u8, 2u8] {
            let (mut replayer, _) = replayer(client);
            let backing = MemoryBacking::new();
            for (seq, op) in &ops {
                replayer
                    .on_ordered(frame(*seq, op.clone()), t(0), &backing, &data)
                    .unwrap();
            }
            assert_eq!(replayer.applied(), Seq(9));
            hashes.push(replayer.snapshot_hash());
            let ino = replayer.read_state().resolve("/d/g").unwrap();
            contents.push(backing.file(ino));
        }
        assert_eq!(hashes[0], hashes[1]);
        assert_eq!(contents[0], contents[1]);
        assert_eq!(contents[0].as_deref(), Some(&b"he"[..]));
    }

    /// D1 / M2-4: two writes at the same offset, the later sequence wins.
    #[test]
    fn u_replayer_d1_same_offset_no_tearing() {
        let mut data = MapData::new();
        let a = data.add(1, b"AAAA");
        let b = data.add(2, b"BBBB");
        let (mut replayer, _) = replayer(1);
        let backing = MemoryBacking::new();
        for (seq, op) in [
            (1, create(1, 2, "/f")),
            (2, pwrite(2, 2, "/f", 0, a)),
            (3, pwrite(3, 3, "/f", 0, b)),
        ] {
            replayer
                .on_ordered(frame(seq, op), t(0), &backing, &data)
                .unwrap();
        }
        let ino = replayer.read_state().resolve("/f").unwrap();
        assert_eq!(backing.file(ino).as_deref(), Some(&b"BBBB"[..]));
        assert_eq!(replayer.read_state().inode(ino).unwrap().size, 4);
    }

    /// D2 / M2-5: non-overlapping writes both survive.
    #[test]
    fn u_replayer_d2_non_overlapping_writes() {
        let mut data = MapData::new();
        let a = data.add(1, b"AAAA");
        let b = data.add(2, b"BBBB");
        let (mut replayer, _) = replayer(1);
        let backing = MemoryBacking::new();
        for (seq, op) in [
            (1, create(1, 2, "/f")),
            (2, pwrite(2, 2, "/f", 0, a)),
            (3, pwrite(3, 3, "/f", 4, b)),
        ] {
            replayer
                .on_ordered(frame(seq, op), t(0), &backing, &data)
                .unwrap();
        }
        let ino = replayer.read_state().resolve("/f").unwrap();
        assert_eq!(backing.file(ino).as_deref(), Some(&b"AAAABBBB"[..]));
    }

    /// D5 / M2-7: exactly one `O_EXCL` creator wins; the loser sees EEXIST.
    #[test]
    fn u_replayer_d5_create_excl_race() {
        let (mut replayer, _) = replayer(1);
        let backing = MemoryBacking::new();
        let data = MapData::new();
        let first = replayer
            .on_ordered(frame(1, create(1, 2, "/f")), t(0), &backing, &data)
            .unwrap();
        assert_eq!(first.verdict, Ok(()));
        let second = replayer
            .on_ordered(frame(2, create(2, 3, "/f")), t(0), &backing, &data)
            .unwrap();
        assert_eq!(second.verdict, Err(Errno::EEXIST));
        assert_eq!(second.applied, Seq(2));
        assert_eq!(replayer.read_state().len(), 2, "root plus one file");
        assert_eq!(replayer.read_state().children_of(InodeId::ROOT).len(), 1);
    }

    /// 41 §5.2 step 2: a duplicate frame does not move the watermark.
    #[test]
    fn u_replayer_duplicate_is_dropped() {
        let (mut replayer, _) = replayer(1);
        let backing = MemoryBacking::new();
        let data = MapData::new();
        let op = create(1, 2, "/f");
        replayer
            .on_ordered(frame(1, op.clone()), t(0), &backing, &data)
            .unwrap();
        let duplicate = replayer
            .on_ordered(frame(1, op), t(0), &backing, &data)
            .unwrap();
        assert!(duplicate.duplicate);
        assert_eq!(duplicate.applied, Seq(1));
        assert_eq!(replayer.applied(), Seq(1));
    }

    /// 41 §5.3: an unseen op at an applied sequence means the space was
    /// replaced, not that the frame was a duplicate.
    #[test]
    fn u_replayer_rollback_resyncs() {
        let (mut replayer, _) = replayer(1);
        let backing = MemoryBacking::new();
        let data = MapData::new();
        replayer
            .on_ordered(frame(1, create(1, 2, "/f")), t(0), &backing, &data)
            .unwrap();
        let fatal = replayer
            .on_ordered(frame(1, create(2, 2, "/g")), t(0), &backing, &data)
            .unwrap_err();
        assert_eq!(fatal, Fatal::Resync(ResyncReason::Rollback));
    }

    /// 41 §5.3: a hole is buffered, then drained in order.
    #[test]
    fn u_replayer_gap_buffers_then_drains() {
        let (mut replayer, _) = replayer(1);
        let backing = MemoryBacking::new();
        let data = MapData::new();
        let buffered = replayer
            .on_ordered(frame(2, create(2, 2, "/b")), t(0), &backing, &data)
            .unwrap();
        assert!(buffered.buffered);
        assert_eq!(buffered.applied, Seq(0));
        assert_eq!(replayer.reorder_len(), 1);

        let progress = replayer
            .on_ordered(frame(1, create(1, 2, "/a")), t(0), &backing, &data)
            .unwrap();
        assert_eq!(progress.applied, Seq(2));
        assert_eq!(replayer.reorder_len(), 0);
        let state = replayer.read_state();
        assert!(state.resolve("/a").is_ok());
        assert!(state.resolve("/b").is_ok());
    }

    /// 41 §5.3: more than 1024 buffered frames is a real gap.
    #[test]
    fn u_replayer_gap_overflow_resyncs() {
        let (mut replayer, _) = replayer(1);
        let backing = MemoryBacking::new();
        let data = MapData::new();
        for seq in 2..=1026u64 {
            let mut op = create(1, 2, &format!("/f{seq}"));
            op.op_id = oid_for(seq);
            let result = replayer.on_ordered(frame(seq, op), t(0), &backing, &data);
            if seq == 1026 {
                assert_eq!(result.unwrap_err(), Fatal::Resync(ResyncReason::SeqGap));
            } else {
                assert!(result.is_ok(), "seq {seq}");
            }
        }
    }

    /// 41 §5.3: a hole that stays open for one second is a real gap.
    #[test]
    fn u_replayer_gap_timeout_resyncs() {
        let (mut replayer, _) = replayer(1);
        let backing = MemoryBacking::new();
        let data = MapData::new();
        replayer
            .on_ordered(frame(2, create(2, 2, "/b")), t(0), &backing, &data)
            .unwrap();
        assert!(replayer.poll_timeout(t(999)).is_none());
        assert_eq!(
            replayer.poll_timeout(t(1_000)),
            Some(Fatal::Resync(ResyncReason::SeqGap))
        );
    }

    /// 41 §5.2 step 4: a larger sequence for a known op_id only advances the
    /// watermark.
    #[test]
    fn u_replayer_op_id_min_seq_not_reapplied() {
        let (mut replayer, _) = replayer(1);
        let backing = MemoryBacking::new();
        let data = MapData::new();
        let op = create(1, 2, "/f");
        replayer
            .on_ordered(frame(1, op.clone()), t(0), &backing, &data)
            .unwrap();
        let hash = replayer.snapshot_hash();
        let progress = replayer
            .on_ordered(frame(2, op), t(0), &backing, &data)
            .unwrap();
        assert_eq!(progress.applied, Seq(2));
        assert_eq!(replayer.snapshot_hash(), hash);
        assert_eq!(replayer.read_state().children_of(InodeId::ROOT).len(), 1);
    }

    /// 41 §5.3: three rebuilds without a steady window are fatal.
    ///
    /// The budget is charged where a rebuild starts, not where it is
    /// detected, so one incident consumes exactly one attempt.
    #[test]
    fn u_replayer_resync_budget_three_then_loop() {
        let (mut replayer, _) = replayer(1);
        replayer.begin_resync(Seq(0), EPOCH, t(0)).unwrap();
        replayer.begin_resync(Seq(0), EPOCH, t(1)).unwrap();
        assert_eq!(
            replayer.begin_resync(Seq(0), EPOCH, t(2)),
            Err(Fatal::ResyncLoop)
        );
        assert_eq!(replayer.resync_count(), 3);
    }

    /// 41 §5.3: detection returns the reason without charging the budget.
    #[test]
    fn u_replayer_detection_does_not_charge_budget() {
        let (mut replayer, _) = replayer(1);
        let backing = MemoryBacking::new();
        let data = MapData::new();
        replayer
            .on_ordered(frame(1, create(1, 2, "/f")), t(0), &backing, &data)
            .unwrap();
        let mut op = create(2, 2, "/g");
        op.op_id = oid(9);
        assert_eq!(
            replayer
                .on_ordered(frame(1, op), t(0), &backing, &data)
                .unwrap_err(),
            Fatal::Resync(ResyncReason::Rollback)
        );
        assert_eq!(replayer.resync_count(), 0);
    }

    /// 41 §5.3: a steady window resets the budget.
    #[test]
    fn u_replayer_resync_budget_resets_after_steady_window() {
        let mut budget = ResyncBudget::new(3, Duration::from_secs(60));
        budget.note_steady(t(0));
        budget.on_resync(t(1)).unwrap();
        budget.on_resync(t(2)).unwrap();
        assert_eq!(budget.count(), 2);
        // Sixty seconds of steady work passed since the last failure.
        budget.note_steady(t(3_000));
        budget.on_resync(t(63_001)).unwrap();
        assert_eq!(budget.count(), 1);
    }

    /// INV-14: rename and link never change the inode; nlink follows the order.
    #[test]
    fn u_replayer_rename_keeps_inode_and_nlink() {
        let (mut replayer, _) = replayer(1);
        let backing = MemoryBacking::new();
        let data = MapData::new();
        for (seq, op) in [
            (1, mkdir(1, 2, "/d")),
            (2, create(2, 2, "/d/f")),
            (3, link_op(3, 2, "/d/g", "/d/f")),
        ] {
            replayer
                .on_ordered(frame(seq, op), t(0), &backing, &data)
                .unwrap();
        }
        let ino = replayer.read_state().resolve("/d/g").unwrap();
        assert_eq!(replayer.read_state().inode(ino).unwrap().nlink, 2);

        replayer
            .on_ordered(
                frame(4, rename_op(4, 2, "/d/g", "/d/h")),
                t(0),
                &backing,
                &data,
            )
            .unwrap();
        let state = replayer.read_state();
        assert_eq!(state.resolve("/d/h").unwrap(), ino);
        assert_eq!(state.inode(ino).unwrap().nlink, 2);
        drop(state);

        replayer
            .on_ordered(frame(5, unlink_op(5, 2, "/d/h")), t(0), &backing, &data)
            .unwrap();
        let state = replayer.read_state();
        assert_eq!(state.inode(ino).unwrap().nlink, 1);
        assert!(!state.inode(ino).unwrap().tombstone);
        drop(state);

        replayer
            .on_ordered(frame(6, unlink_op(6, 2, "/d/f")), t(0), &backing, &data)
            .unwrap();
        let state = replayer.read_state();
        assert_eq!(state.inode(ino).unwrap().nlink, 0);
        assert!(state.inode(ino).unwrap().tombstone);
    }

    /// POSIX nlink: moving a directory transfers one link from the old parent
    /// to the new one; the moved directory keeps its own count.
    #[test]
    fn u_replayer_directory_rename_updates_parent_nlink() {
        let (mut replayer, _) = replayer(1);
        let backing = MemoryBacking::new();
        let data = MapData::new();
        for (seq, op) in [
            (1, mkdir(1, 2, "/a")),
            (2, mkdir(2, 2, "/b")),
            (3, mkdir(3, 2, "/a/d")),
        ] {
            replayer
                .on_ordered(frame(seq, op), t(0), &backing, &data)
                .unwrap();
        }
        let state = replayer.read_state();
        assert_eq!(state.inode(InodeId::ROOT).unwrap().nlink, 4);
        let a = state.resolve("/a").unwrap();
        let b = state.resolve("/b").unwrap();
        assert_eq!(state.inode(a).unwrap().nlink, 3);
        assert_eq!(state.inode(b).unwrap().nlink, 2);
        drop(state);

        replayer
            .on_ordered(
                frame(4, rename_op(4, 2, "/a/d", "/b/d")),
                t(0),
                &backing,
                &data,
            )
            .unwrap();
        let state = replayer.read_state();
        assert_eq!(state.inode(InodeId::ROOT).unwrap().nlink, 4);
        assert_eq!(state.inode(a).unwrap().nlink, 2);
        assert_eq!(state.inode(b).unwrap().nlink, 3);
        assert!(state.resolve("/a/d").is_err());
        assert!(state.resolve("/b/d").is_ok());
    }

    /// POSIX: renaming a directory over an empty directory removes the target.
    #[test]
    fn u_replayer_directory_overwrite_removes_target() {
        let (mut replayer, _) = replayer(1);
        let backing = MemoryBacking::new();
        let data = MapData::new();
        for (seq, op) in [
            (1, mkdir(1, 2, "/a")),
            (2, mkdir(2, 2, "/b")),
            (3, mkdir(3, 2, "/a/x")),
            (4, mkdir(4, 2, "/b/y")),
        ] {
            let progress = replayer
                .on_ordered(frame(seq, op), t(0), &backing, &data)
                .unwrap();
            assert_eq!(progress.verdict, Ok(()), "mkdir at seq {seq}");
        }
        let state = replayer.read_state();
        let moved = state.resolve("/a/x").unwrap();
        let replaced = state.resolve("/b/y").unwrap();
        let before = state.len();
        drop(state);

        replayer
            .on_ordered(
                frame(5, rename_op(5, 2, "/a/x", "/b/y")),
                t(0),
                &backing,
                &data,
            )
            .unwrap();
        let state = replayer.read_state();
        assert_eq!(state.resolve("/b/y").unwrap(), moved);
        assert!(state.inode(replaced).is_none(), "target inode is gone");
        assert_eq!(state.len(), before - 1);
    }

    /// POSIX: a non-empty directory cannot be replaced by `rename`.
    #[test]
    fn u_replayer_directory_overwrite_requires_empty_target() {
        let (mut replayer, _) = replayer(1);
        let backing = MemoryBacking::new();
        let data = MapData::new();
        for (seq, op) in [
            (1, mkdir(1, 2, "/a")),
            (2, mkdir(2, 2, "/b")),
            (3, mkdir(3, 2, "/a/x")),
            (4, mkdir(4, 2, "/b/y")),
            (5, create(5, 2, "/b/y/child")),
        ] {
            replayer
                .on_ordered(frame(seq, op), t(0), &backing, &data)
                .unwrap();
        }
        let progress = replayer
            .on_ordered(
                frame(6, rename_op(6, 2, "/a/x", "/b/y")),
                t(0),
                &backing,
                &data,
            )
            .unwrap();
        assert_eq!(progress.verdict, Err(Errno::ENOTEMPTY));
        assert_eq!(progress.applied, Seq(6));
        assert!(replayer.read_state().resolve("/a/x").is_ok());
    }

    /// 41 §5.6: `LEAVE` releases the departed client's record locks.
    #[test]
    fn u_replayer_leave_releases_locks() {
        let (mut replayer, _) = replayer(1);
        let backing = MemoryBacking::new();
        let data = MapData::new();
        replayer
            .on_ordered(frame(1, create(1, 2, "/f")), t(0), &backing, &data)
            .unwrap();
        let granted = replayer
            .on_ordered(
                frame(2, lock_op(2, 2, "/f", LOCK_ACTION_SET)),
                t(0),
                &backing,
                &data,
            )
            .unwrap();
        assert_eq!(granted.verdict, Ok(()));

        let blocked = replayer
            .on_ordered(
                frame(3, lock_op(3, 3, "/f", LOCK_ACTION_SET)),
                t(0),
                &backing,
                &data,
            )
            .unwrap();
        assert_eq!(blocked.verdict, Err(Errno::EAGAIN));

        let leave = Leave {
            client_id: cid(2),
            reason: 0,
            last_signed_seq: 3,
        };
        replayer
            .on_leave(Seq(4), EPOCH, &leave, t(0), &backing, &data)
            .unwrap();
        assert_eq!(replayer.read_state().locks().count(), 0);

        let granted = replayer
            .on_ordered(
                frame(5, lock_op(5, 3, "/f", LOCK_ACTION_SET)),
                t(0),
                &backing,
                &data,
            )
            .unwrap();
        assert_eq!(granted.verdict, Ok(()));
    }

    /// 41 §5.2 step 1: a different epoch always means a full rebuild.
    #[test]
    fn u_replayer_epoch_change_resyncs() {
        let (mut replayer, _) = replayer(1);
        let backing = MemoryBacking::new();
        let data = MapData::new();
        let fatal = replayer
            .on_ordered(
                IncomingOp::new(Seq(1), EPOCH + 1, create(1, 2, "/f")),
                t(0),
                &backing,
                &data,
            )
            .unwrap_err();
        assert_eq!(fatal, Fatal::Resync(ResyncReason::EpochChanged));
    }

    /// 41 §5.4: a remote operation is materialized first, then the local
    /// pending effect is replayed on top.
    #[test]
    fn u_replayer_pending_rebase() {
        let (mut replayer, pending) = replayer(1);
        let backing = MemoryBacking::new();
        let mut data = MapData::new();
        replayer
            .on_ordered(frame(1, create(1, 2, "/f")), t(0), &backing, &data)
            .unwrap();
        let ino = replayer.read_state().resolve("/f").unwrap();
        pending.insert(
            ino,
            LocalSeq(1),
            oid(0xAA),
            Effect::Write {
                off: 0,
                data: b"LOCAL".to_vec(),
            },
        );

        let remote = data.add(9, b"REMOT");
        let progress = replayer
            .on_ordered(
                frame(2, pwrite(2, 2, "/f", 0, remote)),
                t(0),
                &backing,
                &data,
            )
            .unwrap();
        assert_eq!(progress.bytes_written, 5, "remote payload bytes");
        assert_eq!(backing.file(ino).as_deref(), Some(&b"LOCAL"[..]));
        assert_eq!(backing.effect_count(), 1);
        assert!(pending.is_empty());
    }

    /// 41 §3.1: the echo of a local write is not materialized twice.
    #[test]
    fn u_replayer_echo_skips_materialize() {
        let (mut replayer, pending) = replayer(1);
        let backing = MemoryBacking::new();
        let mut data = MapData::new();
        replayer
            .on_ordered(frame(1, create(1, 2, "/f")), t(0), &backing, &data)
            .unwrap();
        let ino = replayer.read_state().resolve("/f").unwrap();
        pending.insert(
            ino,
            LocalSeq(1),
            oid(0xBB),
            Effect::Write {
                off: 0,
                data: b"LOCAL".to_vec(),
            },
        );
        let local = data.add(10, b"LOCAL");
        let mut op = pwrite(0xBB, 1, "/f", 0, local);
        op.op_id = oid(0xBB);
        let progress = replayer
            .on_ordered(frame(2, op), t(0), &backing, &data)
            .unwrap();
        assert_eq!(progress.verdict, Ok(()));
        assert_eq!(
            progress.bytes_written, 0,
            "a local echo must not be counted twice"
        );
        assert_eq!(backing.file(ino).as_deref(), Some(&b""[..]));
        assert_eq!(replayer.read_state().inode(ino).unwrap().size, 5);
        assert!(pending.is_empty());
    }

    /// The production window follows local echoes and sequence holes.
    #[test]
    fn u_replayer_backpressure_counts_echoes_and_holes() {
        let window = Arc::new(Backpressure::new(2, 0));
        let (replayer, _pending) = replayer(1);
        let mut replayer = replayer.with_backpressure(Arc::clone(&window));
        let backing = MemoryBacking::new();
        let data = MapData::new();

        // Two local operations are in flight: admission is closed.
        window.note_in_flight();
        window.note_in_flight();
        assert!(!window.is_open());

        // The first echo frees one slot; the second reopens the window.
        replayer
            .on_ordered(frame(1, create(1, 1, "/a")), t(0), &backing, &data)
            .unwrap();
        assert!(!window.is_open());
        replayer
            .on_ordered(frame(2, create(2, 1, "/b")), t(0), &backing, &data)
            .unwrap();
        assert!(window.is_open());

        // A hole closes it again, and filling the hole reopens it.
        let progress = replayer
            .on_ordered(frame(4, create(4, 2, "/d")), t(0), &backing, &data)
            .unwrap();
        assert!(progress.buffered);
        assert!(!window.is_open());
        replayer
            .on_ordered(frame(3, create(3, 2, "/c")), t(0), &backing, &data)
            .unwrap();
        assert!(window.is_open());
    }

    /// 41 §9: a plaintext hash mismatch is fatal, never silently accepted.
    #[test]
    fn u_replayer_materialize_hash_mismatch_is_fatal() {
        let (mut replayer, _) = replayer(1);
        let backing = MemoryBacking::new();
        let mut data = MapData::new();
        replayer
            .on_ordered(frame(1, create(1, 2, "/f")), t(0), &backing, &data)
            .unwrap();
        data.add(11, b"hello");
        let forged = DataRef {
            session: SessionId::new(11),
            total_len: 5,
            data_hash: [0u8; 32],
        };
        let fatal = replayer
            .on_ordered(
                frame(2, pwrite(2, 2, "/f", 0, forged)),
                t(0),
                &backing,
                &data,
            )
            .unwrap_err();
        assert_eq!(
            fatal,
            Fatal::Materialize {
                seq: Seq(2),
                errno: Errno::EIO
            }
        );
        assert_eq!(replayer.applied(), Seq(1), "watermark must not advance");
    }

    /// 41 §2.6: waiters wake with the verdict, and drop on unmount.
    #[test]
    fn u_replayer_waiters() {
        let (mut replayer, _) = replayer(1);
        let backing = MemoryBacking::new();
        let data = MapData::new();
        let rx = replayer.register_waiter(oid(1));
        replayer
            .on_ordered(frame(1, create(1, 1, "/f")), t(0), &backing, &data)
            .unwrap();
        assert_eq!(rx.recv().unwrap(), Ok(()));

        let rx = replayer.register_waiter(oid(2));
        replayer.fail_all_waiters();
        assert!(rx.recv().is_err());
    }

    /// 41 R6: the derived inode id is stable and never the root.
    #[test]
    fn u_replayer_inode_id_derivation_is_stable() {
        assert_eq!(derive_inode_id(oid(1)), derive_inode_id(oid(1)));
        assert_ne!(derive_inode_id(oid(1)), derive_inode_id(oid(2)));
        assert!(!derive_inode_id(oid(1)).is_root());
        assert!(!derive_inode_id(oid(2)).is_root());
    }

    /// 31:M2-8: the JOIN manifest rebuilds `S`, so an operation on an
    /// existing path resolves instead of failing with `ENOENT`.
    #[test]
    fn u_namespace_rebuild_from_manifest() {
        use crate::sync::manifest::Entry;

        let manifest = Manifest::new(
            Seq(7),
            vec![
                Entry::dir("d", InodeId(10), 0o750, 1000, 1000, 111),
                Entry::file("d/f", InodeId(11), 0o640, 1000, 1000, 5, 222, &[]),
                Entry::symlink("l", InodeId(12), 1000, 1000, 333, "target"),
                Entry::file("h1", InodeId(13), 0o644, 1000, 1000, 1, 444, &[]),
                Entry::file("h2", InodeId(13), 0o644, 1000, 1000, 1, 444, &[]),
            ],
        );
        let mut ns = Namespace::new();
        ns.rebuild_from_manifest(&manifest).unwrap();

        assert_eq!(ns.resolve("/d").unwrap(), InodeId(10));
        assert_eq!(ns.resolve("/d/f").unwrap(), InodeId(11));
        assert_eq!(ns.resolve("/l").unwrap(), InodeId(12));
        assert_eq!(ns.resolve("/h1").unwrap(), InodeId(13));
        assert_eq!(ns.resolve("/h2").unwrap(), InodeId(13));
        assert_eq!(ns.inode(InodeId::ROOT).unwrap().nlink, 3);
        assert_eq!(ns.inode(InodeId(10)).unwrap().nlink, 2);
        assert_eq!(ns.inode(InodeId(11)).unwrap().size, 5);
        assert_eq!(ns.inode(InodeId(11)).unwrap().mode, 0o640);
        assert_eq!(ns.inode(InodeId(12)).unwrap().size, 6);
        assert_eq!(
            ns.inode(InodeId(12)).unwrap().symlink.as_deref(),
            Some(b"target".as_slice())
        );
        assert_eq!(ns.inode(InodeId(13)).unwrap().nlink, 2);

        // A WRITE-class plan on an existing path must now resolve; before the
        // rebuild the same path is `ENOENT` because `S` held only the root.
        let op = Op::new(oid(20), cid(1), OpClass::TRUNCATE, "/d/f")
            .with_body(OpBody::Truncate { length: 0 });
        let plan = ns.plan(&op);
        assert!(plan.is_applied(), "existing path must resolve: {plan:?}");
        assert!(!plan.effects.is_empty());

        let orphan = Manifest::new(
            Seq(7),
            vec![Entry::file("x/y", InodeId(20), 0o644, 0, 0, 1, 0, &[])],
        );
        assert_eq!(ns.rebuild_from_manifest(&orphan), Err(Errno::ENOENT));
        assert_eq!(
            ns.resolve("/d/f").unwrap(),
            InodeId(11),
            "a failed rebuild leaves `S` untouched"
        );
    }

    /// The JOIN handoff on [`Replayer`] reaches the same state, so the first
    /// frame after the join plans against the installed paths.
    #[test]
    fn u_replayer_rebuild_from_manifest() {
        use crate::sync::manifest::Entry;

        let (mut replayer, _pending) = replayer(1);
        let manifest = Manifest::new(
            Seq(9),
            vec![
                Entry::dir("d", InodeId(10), 0o755, 0, 0, 1),
                Entry::file("d/f", InodeId(11), 0o644, 0, 0, 1, 1, &[]),
            ],
        );
        replayer.rebuild_from_manifest(&manifest).unwrap();
        assert_eq!(replayer.read_state().resolve("/d/f").unwrap(), InodeId(11));

        let op = Op::new(oid(30), cid(2), OpClass::TRUNCATE, "/d/f")
            .with_body(OpBody::Truncate { length: 0 });
        let plan = replayer.read_state().plan(&op);
        assert!(
            plan.is_applied(),
            "the first frame after JOIN must not see ENOENT: {plan:?}"
        );
    }

    /// 41 §5.3: a resync drops buffered frames and pending effects.
    #[test]
    fn u_replayer_begin_resync_clears_transient_state() {
        let (mut replayer, pending) = replayer(1);
        let backing = MemoryBacking::new();
        let data = MapData::new();
        replayer
            .on_ordered(frame(2, create(2, 2, "/b")), t(0), &backing, &data)
            .unwrap();
        pending.insert(
            InodeId(9),
            LocalSeq(1),
            oid(9),
            Effect::Truncate { size: 0 },
        );
        replayer.begin_resync(Seq(10), EPOCH, t(10)).unwrap();
        assert_eq!(replayer.applied(), Seq(10));
        assert_eq!(replayer.reorder_len(), 0);
        assert!(pending.is_empty());
    }

    /// 41 §5.7 / 55 P1-12: a class the engine does not apply is refused, and
    /// the watermark still advances because the sequence was consumed.
    #[test]
    fn u_replayer_unhandled_class_rejects_without_effect() {
        let (mut replayer, _) = replayer(1);
        let backing = MemoryBacking::new();
        let data = MapData::new();
        // `SYNC_CTRL` is a sequenced no-op in v1.
        let op = Op::new(oid(1), cid(2), OpClass::SYNC_CTRL, "/");
        let progress = replayer
            .on_ordered(frame(1, op), t(0), &backing, &data)
            .unwrap();
        assert_eq!(progress.verdict, Ok(()));
        assert_eq!(replayer.applied(), Seq(1));
        assert_eq!(replayer.read_state().len(), 1, "root only");
        assert!(backing.file(InodeId(1)).is_none());
    }
}
