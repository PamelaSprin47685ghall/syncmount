//! W13b: the FUSE write path.
//!
//! Every mutating callback follows the same five steps (41 §3.1):
//!
//! 1. [`WriteGate::check_write`] — `JOINING`/`DEGRADED_RO` answer `EROFS`;
//!    `UNMOUNTING` and every pre-mount state answer `ENOTCONN`.
//! 2. [`Outbox::reserve`] — admission happens before the backing tree is
//!    touched, so a full queue answers `ENOSPC` with the disk unchanged.
//! 3. [`Outbox::alloc_seq`] — the sequence is the right half of the
//!    [`OpId`]; the instance id is the left half (44 §0).
//! 4. The local backing change. The application only ever sees this result.
//! 5. `Reservation::commit` — a success reply means "already queued".
//!
//! Data operations register their optimistic effect in [`PendingOverlay`]
//! *before* the disk write, so the echo of our own operation skips
//! re-materialisation. Metadata operations have no `Effect` variant; their
//! echoes are absorbed by [`super::ReplayView`], which treats an already
//! applied creation/removal as a no-op.
//!
//! # Metadata bodies
//!
//! [`LocalOp::Meta`] carries an encoded operation body. This module encodes
//! the WCP field set that [`crate::protocol::messages::Ordered`] decodes,
//! minus the envelope fields the uplink adds at seal time (`F_KEY_EPOCH`,
//! `F_PAYLOAD_HASH`, `F_SIG`): class, path, attributes and the class-specific
//! arguments. The writer never interprets the body; the uplink only appends
//! the envelope and signs it.
//!
//! Reads are not here. `lookup`/`getattr`/`read`/`readdir` stay on the local
//! backing tree and never touch the network (41 §4).

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::client::replayer::{Lock, LockKey, LockType};
use crate::client::{InstanceId, LocalOp, LocalSeq, Outbox, PendingOverlay, SyncHandle, WriteGate};
use crate::protocol::frame::{ClientId, OpId};
use crate::protocol::messages::{OpClass, WcpWriter, fid};
use crate::store::node_table::InodeId;
use crate::store::{Attr, AttrDelta, BackingStore, Effect, Errno, NodeTable};

use super::fs::FuseBacking;

/// How long a metadata callback waits for its own operation to be applied.
///
/// The wait ends early on disconnect (the replayer drops every waiter); this
/// ceiling only covers a link that is up but silent. A timeout answers
/// `ENOTCONN`, the same errno as an unmounted session.
const ECHO_TIMEOUT: Duration = Duration::from_secs(10);

/// A shared handle to the client's admission queue and write gate.
///
/// It holds no replay state: the replayer owns `S(seq)`, and this type only
/// turns kernel callbacks into `LocalOp`s.
#[derive(Clone, Debug)]
pub struct WritePath {
    gate: Arc<WriteGate>,
    outbox: Arc<Outbox>,
    pending: Arc<PendingOverlay>,
    /// The replay engine's applied state and echo waiters, when one exists.
    sync: Option<SyncHandle>,
    instance: InstanceId,
    client_id: ClientId,
}

impl WritePath {
    /// Assemble the adapter from the client's shared parts.
    pub fn new(
        gate: Arc<WriteGate>,
        outbox: Arc<Outbox>,
        pending: Arc<PendingOverlay>,
        instance: InstanceId,
        client_id: ClientId,
    ) -> Self {
        Self {
            gate,
            outbox,
            pending,
            sync: None,
            instance,
            client_id,
        }
    }

    /// Attach the replay engine handle.
    ///
    /// With a live handle, namespace metadata waits for its own echo before
    /// the callback replies; without one, the adapter is a standalone local
    /// filesystem and keeps the local-only behaviour.
    pub fn with_sync(mut self, sync: SyncHandle) -> Self {
        self.sync = Some(sync);
        self
    }

    /// Whether metadata operations are arbitrated by a replay engine.
    pub fn arbitrated(&self) -> bool {
        self.sync.as_ref().is_some_and(SyncHandle::is_live)
    }

    /// Whether this path belongs to a cluster client (a handle exists even
    /// before the JOIN attaches the replayer).
    pub fn has_sync(&self) -> bool {
        self.sync.is_some()
    }

    /// The write gate shared with the lifecycle driver.
    pub fn gate(&self) -> &WriteGate {
        &self.gate
    }

    /// The client instance (left half of every `op_id`).
    pub const fn instance(&self) -> InstanceId {
        self.instance
    }

    /// The stable client identity.
    pub const fn client_id(&self) -> ClientId {
        self.client_id
    }

    /// Admit one operation of `bytes` payload.
    ///
    /// The gate is checked first, then capacity is reserved. A caller that
    /// fails after this point drops the [`Admission`]: the capacity is
    /// returned and the sequence is skipped, so a failed local operation
    /// cannot stall the queue. This is what makes an early `?` safe.
    pub fn admit(&self, bytes: usize) -> Result<Admission<'_>, Errno> {
        self.gate.check_write()?;
        let reservation = self.outbox.reserve(bytes).map_err(|_| Errno::ENOSPC)?;
        let seq = self.outbox.alloc_seq();
        Ok(Admission {
            reservation: Some(reservation),
            outbox: &self.outbox,
            pending: &self.pending,
            tracked: false,
            seq,
            op_id: op_id_for(self.instance, seq),
        })
    }

    /// Write data locally and queue the operation.
    ///
    /// The reservation is taken before the disk write; the pending effect is
    /// registered before the disk write as well. A failed write returns the
    /// errno and leaves the outbox untouched (39 §2.1, 41 §3.1).
    pub fn write<B: FuseBacking + ?Sized>(
        &self,
        store: &B,
        ino: InodeId,
        offset: u64,
        data: &[u8],
    ) -> Result<usize, Errno> {
        let mut admission = self.admit(data.len())?;
        admission.track(
            ino,
            Effect::Write {
                off: offset,
                data: data.to_vec(),
            },
        );
        match BackingStore::write_at(store, ino, offset, data) {
            Ok(count) if count == data.len() => {
                admission.commit(LocalOp::Write {
                    ino,
                    off: offset,
                    data: data.to_vec(),
                });
                Ok(count)
            }
            // A zero-length result is a legal short write: nothing reached the
            // file, so nothing is queued.
            Ok(0) => {
                admission.abort();
                Ok(0)
            }
            // `BackingStore::write_at` promises a complete write, but a
            // wrapper may still return a short count. Queue exactly what the
            // disk accepted; the caller gets the POSIX count.
            Ok(count) => {
                let prefix = data[..count].to_vec();
                admission.retrack(
                    ino,
                    Effect::Write {
                        off: offset,
                        data: prefix.clone(),
                    },
                );
                admission.commit(LocalOp::Write {
                    ino,
                    off: offset,
                    data: prefix,
                });
                Ok(count)
            }
            Err(err) => {
                admission.abort();
                Err(err)
            }
        }
    }

    /// Truncate locally and queue the operation.
    pub fn truncate<B: FuseBacking + ?Sized>(
        &self,
        store: &B,
        ino: InodeId,
        size: u64,
    ) -> Result<(), Errno> {
        let mut admission = self.admit(0)?;
        admission.track(ino, Effect::Truncate { size });
        match BackingStore::truncate(store, ino, size) {
            Ok(()) => {
                admission.commit(LocalOp::Truncate { ino, size });
                Ok(())
            }
            Err(err) => {
                admission.abort();
                Err(err)
            }
        }
    }

    /// Apply attributes locally and queue the operation.
    ///
    /// `size` is a `TRUNCATE` on the wire, every other field is `SETATTR`;
    /// a single `setattr` syscall that changes both becomes two operations in
    /// that order (39 §2.3).
    pub fn set_attr<B: FuseBacking + ?Sized>(
        &self,
        store: &B,
        ino: InodeId,
        delta: &AttrDelta,
    ) -> Result<(), Errno> {
        let rest = AttrDelta {
            size: None,
            ..*delta
        };
        let mut truncate = match delta.size {
            Some(size) => Some((self.admit(0)?, size)),
            None => None,
        };
        let mut attrs = if rest == AttrDelta::default() {
            None
        } else {
            Some(self.admit(0)?)
        };
        if let Some((admission, size)) = truncate.as_mut() {
            admission.track(ino, Effect::Truncate { size: *size });
        }
        if let Some(admission) = attrs.as_mut() {
            admission.track(ino, Effect::SetAttr(rest));
        }
        match BackingStore::set_attr(store, ino, delta) {
            Ok(()) => {
                if let Some((admission, size)) = truncate {
                    admission.commit(LocalOp::Truncate { ino, size });
                }
                if let Some(admission) = attrs {
                    admission.commit(LocalOp::SetAttr { ino, delta: rest });
                }
                Ok(())
            }
            Err(err) => {
                if let Some((admission, _)) = truncate {
                    admission.abort();
                }
                if let Some(admission) = attrs {
                    admission.abort();
                }
                Err(err)
            }
        }
    }

    /// Set or remove one extended attribute locally and queue the operation.
    pub fn set_xattr<B: FuseBacking + ?Sized>(
        &self,
        store: &B,
        ino: InodeId,
        name: &OsStr,
        value: Option<&[u8]>,
        flags: i32,
    ) -> Result<(), Errno> {
        let name = name.as_bytes().to_vec();
        let value = value.map(<[u8]>::to_vec);
        let bytes = name.len() + value.as_ref().map_or(0, Vec::len);
        let mut admission = self.admit(bytes)?;
        admission.track(
            ino,
            Effect::Xattr {
                name: name.clone(),
                value: value.clone(),
            },
        );
        let result = match value.as_deref() {
            Some(bytes) => store.setxattr(ino, OsStr::from_bytes(&name), bytes, flags),
            None => store.removexattr(ino, OsStr::from_bytes(&name)),
        };
        match result {
            Ok(()) => {
                admission.commit(LocalOp::Xattr { ino, name, value });
                Ok(())
            }
            Err(err) => {
                admission.abort();
                Err(err)
            }
        }
    }

    /// Flush one inode to the local disk and ask the uplink to send it.
    ///
    /// `fsync` never waits for an echo; it only promises local persistence
    /// and that the operation has been handed to the network (39 §2.1).
    pub fn fsync<B: FuseBacking + ?Sized>(
        &self,
        store: &B,
        ino: InodeId,
        datasync: bool,
    ) -> Result<(), Errno> {
        BackingStore::fsync(store, ino, datasync)?;
        self.outbox.flush_hint(ino);
        Ok(())
    }

    /// Queue a metadata operation whose disk effect has already happened.
    ///
    /// The body is built here, not by the caller, so every `LocalOp::Meta`
    /// carries the same field set regardless of the callback that produced it.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_meta(
        &self,
        admission: Admission<'_>,
        class: OpClass,
        ino: Option<InodeId>,
        path: String,
        args: MetaArgs<'_>,
        owner: MetaOwner,
    ) -> Result<(), Errno> {
        let body = MetaOp {
            class,
            path,
            args,
            owner,
        }
        .encode(admission.op_id, self.client_id)?;
        admission.commit(LocalOp::Meta { ino, class, body });
        Ok(())
    }

    /// Queue a metadata operation and wait for its own replay verdict.
    ///
    /// This is L2 synchronous arbitration (39 §2.1): the caller has already
    /// reserved capacity and a sequence, the operation is now visible to the
    /// uplink, and the callback blocks until the replayer applies that exact
    /// `op_id`. The disk is changed by the replay engine, not by the caller,
    /// so a rejected operation leaves the local tree untouched.
    ///
    /// Without a live [`SyncHandle`] there is no sequence to wait for; the
    /// callback answers `ENOTCONN` because this path never applied the change
    /// locally: a metadata callback chooses between this function and the
    /// local-first one before it reserves anything.
    ///
    /// A wait that ends without an echo (disconnect, resync, or the ceiling
    /// below) is reported as `ENOTCONN`. The operation may still be applied
    /// later if the link recovers; the caller must treat it as unconfirmed.
    pub fn commit_meta_sync(
        &self,
        admission: Admission<'_>,
        class: OpClass,
        ino: Option<InodeId>,
        path: String,
        args: MetaArgs<'_>,
        owner: MetaOwner,
    ) -> Result<(), Errno> {
        let op_id = admission.op_id;
        let body = MetaOp {
            class,
            path,
            args,
            owner,
        }
        .encode(op_id, self.client_id)?;
        // Register before the operation can be echoed: once `commit` returns,
        // the uplink may already have sent it and the replayer may answer.
        let waiter = self.sync.as_ref().and_then(|sync| sync.register(op_id));
        admission.commit(LocalOp::Meta { ino, class, body });
        let Some(waiter) = waiter else {
            return Err(Errno(libc::ENOTCONN));
        };
        match waiter.recv_timeout(ECHO_TIMEOUT) {
            Ok(verdict) => verdict,
            Err(RecvTimeoutError::Timeout) => {
                if let Some(sync) = &self.sync {
                    sync.cancel(op_id);
                }
                Err(Errno(libc::ENOTCONN))
            }
            Err(RecvTimeoutError::Disconnected) => Err(Errno(libc::ENOTCONN)),
        }
    }

    /// The first foreign lock that would block `typ` on `[start, end]`.
    pub fn lock_conflict(
        &self,
        ino: InodeId,
        start: u64,
        end: u64,
        typ: LockType,
    ) -> Option<(LockKey, Lock)> {
        self.sync
            .as_ref()?
            .find_lock(ino, start, end, typ, self.client_id)
    }
}

/// One admitted operation: capacity is charged and a sequence is allocated.
///
/// Dropping an uncommitted admission returns the capacity and removes any
/// pending effect it registered.
#[derive(Debug)]
pub struct Admission<'a> {
    reservation: Option<crate::client::writer::Reservation<'a>>,
    outbox: &'a Outbox,
    pending: &'a PendingOverlay,
    tracked: bool,
    /// The allocated local sequence.
    pub seq: LocalSeq,
    /// The operation identifier derived from `(instance, seq)`.
    pub op_id: OpId,
}

impl Admission<'_> {
    /// Register the optimistic effect applied by this operation.
    pub fn track(&mut self, ino: InodeId, effect: Effect) {
        self.pending.insert(ino, self.seq, self.op_id, effect);
        self.tracked = true;
    }

    /// Replace the optimistic effect (short write).
    pub fn retrack(&mut self, ino: InodeId, effect: Effect) {
        let _ = self.pending.take(self.op_id);
        self.pending.insert(ino, self.seq, self.op_id, effect);
        self.tracked = true;
    }

    /// Commit the operation to the outbox.
    pub fn commit(mut self, op: LocalOp) {
        if let Some(reservation) = self.reservation.take() {
            reservation.commit(self.seq, self.op_id, op);
        }
        self.tracked = false;
    }

    /// Drop the operation and return its capacity.
    pub fn abort(mut self) {
        if self.tracked {
            let _ = self.pending.take(self.op_id);
            self.tracked = false;
        }
        if self.reservation.take().is_some() {
            // The sequence was allocated but will never be sent. Closing the
            // hole keeps every later operation flowing.
            self.outbox.skip(self.seq);
        }
    }
}

impl Drop for Admission<'_> {
    fn drop(&mut self) {
        if self.reservation.is_some() {
            if self.tracked {
                let _ = self.pending.take(self.op_id);
            }
            // Dropping the reservation returns the capacity; the sequence is
            // abandoned so the uplink does not wait for it.
            self.reservation = None;
            self.outbox.skip(self.seq);
        }
    }
}

/// The 16-byte operation id: `instance` (8B LE) ‖ `local_seq` (8B LE).
pub fn op_id_for(instance: InstanceId, seq: LocalSeq) -> OpId {
    let mut raw = [0u8; 16];
    raw[..8].copy_from_slice(&instance.0.to_le_bytes());
    raw[8..].copy_from_slice(&seq.0.to_le_bytes());
    OpId::from_bytes(raw)
}

/// Class-specific arguments of a metadata operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetaArgs<'a> {
    /// No extra arguments (`UNLINK`, `RMDIR`).
    None,
    /// Mode (`MKDIR`).
    Mode(u32),
    /// Mode and open flags (`CREATE_EXCL`).
    ModeFlags {
        /// Creation mode.
        mode: u32,
        /// Open flags.
        flags: u32,
    },
    /// Destination path (`RENAME`).
    Rename {
        /// Absolute destination path.
        path2: &'a str,
    },
    /// Existing target path (`LINK`).
    Link {
        /// Absolute path of the existing inode.
        target: &'a str,
    },
    /// Link contents (`SYMLINK`).
    Symlink {
        /// Symbolic-link target.
        target: &'a str,
    },
    /// Record lock (`FCNTL_LOCK`).
    FcntlLock {
        /// `0` shared, `1` exclusive.
        lock_type: u8,
        /// [`LOCK_ACTION_SET`] or [`LOCK_ACTION_UNLOCK`].
        action: u8,
        /// First byte.
        start: u64,
        /// Byte count; `0` means "to end of file".
        len: u64,
    },
}

/// Who owns a metadata operation and when it happened.
///
/// The wire carries `F_UID`, `F_GID` and `F_MTIME_NS` on every file
/// operation. A synchronous metadata callback builds them from the FUSE
/// request before the inode exists; the local-only path reads them back from
/// the inode it just created.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MetaOwner {
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// Modification time, nanoseconds since the Unix epoch.
    pub mtime_ns: u64,
}

impl MetaOwner {
    /// The owner of a local change, as recorded by the backing store.
    pub fn from_attr(attr: &Attr) -> Self {
        let seconds = attr.mtime.sec.max(0) as u64;
        let nanos = attr.mtime.nsec.clamp(0, 999_999_999) as u64;
        Self {
            uid: attr.uid,
            gid: attr.gid,
            mtime_ns: seconds.saturating_mul(1_000_000_000).saturating_add(nanos),
        }
    }

    /// The owner of a FUSE request, stamped with the current time.
    pub fn request(uid: u32, gid: u32) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos().min(u128::from(u64::MAX)) as u64)
            .unwrap_or_default();
        Self {
            uid,
            gid,
            mtime_ns: nanos,
        }
    }
}

/// A metadata operation ready for WCP encoding.
struct MetaOp<'a> {
    class: OpClass,
    path: String,
    args: MetaArgs<'a>,
    owner: MetaOwner,
}

impl MetaOp<'_> {
    /// Encode the plaintext WCP body, minus the envelope the uplink adds.
    fn encode(&self, op_id: OpId, client_id: ClientId) -> Result<Vec<u8>, Errno> {
        let mut writer = WcpWriter::new();
        writer.u8(fid::F_OP_CLASS, self.class.get());
        writer.str(fid::F_PATH, &self.path);
        writer.bytes(fid::F_OP_ID, op_id.as_bytes());
        writer.bytes(fid::F_CLIENT_ID, client_id.as_bytes());
        writer.u32(fid::F_UID, self.owner.uid);
        writer.u32(fid::F_GID, self.owner.gid);
        writer.u64(fid::F_MTIME_NS, self.owner.mtime_ns);
        match self.args {
            MetaArgs::None => {}
            MetaArgs::Mode(mode) => {
                writer.u32(fid::F_MODE, mode);
            }
            MetaArgs::ModeFlags { mode, flags } => {
                writer.u32(fid::F_MODE, mode);
                writer.u32(fid::F_OP_FLAGS, flags);
            }
            MetaArgs::Rename { path2 } => {
                writer.str(fid::F_PATH2, path2);
            }
            MetaArgs::Link { target } | MetaArgs::Symlink { target } => {
                writer.str(fid::F_TARGET, target);
            }
            MetaArgs::FcntlLock {
                lock_type,
                action,
                start,
                len,
            } => {
                writer.u8(fid::F_LOCK_TYPE, lock_type);
                writer.u8(fid::F_LOCK_ACTION, action);
                writer.u64(fid::F_LOCK_START, start);
                writer.u64(fid::F_LOCK_LEN, len);
            }
        }
        writer.finish().map_err(|_| Errno::EINVAL)
    }
}

/// Absolute path of `id`, or `EINVAL` when it is not valid UTF-8.
pub(crate) fn absolute_path(nodes: &NodeTable, id: InodeId) -> Result<String, Errno> {
    let relative = nodes.path_of(id).ok_or(Errno::ENOENT)?;
    if relative.as_os_str().is_empty() {
        return Ok("/".to_string());
    }
    let text = relative.to_str().ok_or(Errno::EINVAL)?;
    Ok(format!("/{text}"))
}

/// Absolute path of `parent/name`, or `EINVAL` when it is not valid UTF-8.
pub(crate) fn child_path(
    nodes: &NodeTable,
    parent: InodeId,
    name: &OsStr,
) -> Result<String, Errno> {
    let parent = absolute_path(nodes, parent)?;
    let name = name.to_str().ok_or(Errno::EINVAL)?;
    if parent == "/" {
        Ok(format!("/{name}"))
    } else {
        Ok(format!("{parent}/{name}"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    use std::sync::Arc;
    use std::time::Duration;

    use tempfile::TempDir;

    use crate::client::{IncomingOp, Op, OpBody, Replayer, Tuning};
    use crate::protocol::frame::Seq;
    use crate::protocol::messages::DataRef;
    use crate::store::{PosixBacking, RootFd};

    struct Fixture {
        _tmp: TempDir,
        backing: Arc<PosixBacking>,
        gate: Arc<WriteGate>,
        outbox: Arc<Outbox>,
        pending: Arc<PendingOverlay>,
        path: WritePath,
    }

    fn fixture() -> Fixture {
        let tmp = TempDir::new().unwrap();
        let root = RootFd::open_before_mount(tmp.path()).unwrap();
        let backing = Arc::new(PosixBacking::new(root));
        let gate = Arc::new(WriteGate::new(crate::client::State::Steady));
        let outbox = Arc::new(Outbox::with_tuning(&Tuning::default()));
        let pending = Arc::new(PendingOverlay::new());
        let path = WritePath::new(
            Arc::clone(&gate),
            Arc::clone(&outbox),
            Arc::clone(&pending),
            InstanceId(7),
            ClientId::from_bytes([9; 16]),
        );
        Fixture {
            _tmp: tmp,
            backing,
            gate,
            outbox,
            pending,
            path,
        }
    }

    fn write_file(fixture: &Fixture, name: &str, data: &[u8]) -> InodeId {
        let id = InodeId::new_v4();
        BackingStore::create(
            fixture.backing.as_ref(),
            InodeId::ROOT,
            OsStr::new(name),
            id,
            0o644,
        )
        .unwrap();
        BackingStore::write_at(fixture.backing.as_ref(), id, 0, data).unwrap();
        id
    }

    /// 41 §3.1 / C-09: the gate refuses before the disk or the outbox move.
    #[test]
    fn u_fuse_write_gate_refuses_mutations() {
        use crate::client::State;
        for (state, expected) in [
            (State::Joining, Errno::EROFS),
            (State::DegradedReadOnly, Errno::EROFS),
            (State::Unmounting, Errno(libc::ENOTCONN)),
            (State::Boot, Errno(libc::ENOTCONN)),
        ] {
            let fixture = fixture();
            let id = write_file(&fixture, "f", b"old");
            fixture.gate.set(state);
            let error = fixture
                .path
                .write(fixture.backing.as_ref(), id, 0, b"new")
                .unwrap_err();
            assert_eq!(error, expected, "state {state:?}");
            assert!(fixture.outbox.is_empty());
            assert!(fixture.pending.is_empty());
            let mut buffer = [0u8; 8];
            let count =
                BackingStore::read_at(fixture.backing.as_ref(), id, 0, &mut buffer).unwrap();
            assert_eq!(&buffer[..count], b"old");
        }
    }

    /// 41 §3.1: a full outbox answers ENOSPC and leaves the disk untouched.
    #[test]
    fn u_fuse_write_outbox_full_is_enospc() {
        let fixture = fixture();
        let outbox = Arc::new(Outbox::new(4, 64));
        let path = WritePath::new(
            Arc::clone(&fixture.gate),
            outbox,
            Arc::clone(&fixture.pending),
            InstanceId(7),
            ClientId::from_bytes([9; 16]),
        );
        let id = write_file(&fixture, "f", b"old");
        assert_eq!(
            path.write(fixture.backing.as_ref(), id, 0, b"0123456789"),
            Err(Errno::ENOSPC)
        );
        assert!(fixture.pending.is_empty());
        let mut buffer = [0u8; 8];
        let count = BackingStore::read_at(fixture.backing.as_ref(), id, 0, &mut buffer).unwrap();
        assert_eq!(&buffer[..count], b"old");
    }

    /// 41 §3.1: a successful write is local and queued before the reply.
    #[test]
    fn u_fuse_write_queues_and_reads_locally() {
        let fixture = fixture();
        let id = write_file(&fixture, "f", b"");
        let count = fixture
            .path
            .write(fixture.backing.as_ref(), id, 2, b"abc")
            .unwrap();
        assert_eq!(count, 3);
        assert_eq!(fixture.outbox.depth().ops, 1);
        assert_eq!(fixture.pending.len(), 1);

        let queued = fixture.outbox.take_ready().unwrap();
        assert_eq!(queued.seq, LocalSeq(1));
        assert_eq!(
            queued.op,
            LocalOp::Write {
                ino: id,
                off: 2,
                data: b"abc".to_vec()
            }
        );

        let mut buffer = [0u8; 8];
        let count = BackingStore::read_at(fixture.backing.as_ref(), id, 0, &mut buffer).unwrap();
        assert_eq!(&buffer[..count], b"\0\0abc");
    }

    /// 41 §3.1: the echo of our own write skips materialisation but advances
    /// `S`, because the pending overlay already holds the effect.
    #[test]
    fn u_fuse_write_echo_skips_materialize() {
        let fixture = fixture();
        let mut replayer = Replayer::new(
            ClientId::from_bytes([9; 16]),
            Seq::UNSEQUENCED,
            1,
            &Tuning::default(),
            Arc::clone(&fixture.pending),
        );
        // Seed `S` (and the disk) from a remote create: the replay engine
        // starts at the JOIN watermark and learns entries from the broadcast.
        let create = IncomingOp::new(
            Seq(1),
            1,
            Op::new(
                OpId::from_bytes([1; 16]),
                ClientId::from_bytes([8; 16]),
                OpClass::CREATE_EXCL,
                "/f",
            )
            .with_body(OpBody::CreateExcl {
                mode: 0o644,
                flags: 0,
            }),
        );
        replayer
            .on_ordered(
                create,
                Duration::ZERO,
                fixture.backing.as_ref(),
                &EchoData(Vec::new()),
            )
            .unwrap();
        let id = replayer.read_state().resolve("/f").unwrap();

        fixture
            .path
            .write(fixture.backing.as_ref(), id, 0, b"hello")
            .unwrap();
        let queued = fixture.outbox.take_ready().unwrap();

        let data = DataRef {
            session: crate::protocol::frame::SessionId::from_le_bytes([0; 16]),
            total_len: 5,
            data_hash: *blake3::hash(b"hello").as_bytes(),
        };
        let echo = IncomingOp::new(
            Seq(2),
            1,
            Op::new(
                queued.op_id,
                ClientId::from_bytes([9; 16]),
                OpClass::WRITE,
                "/f",
            )
            .with_body(OpBody::Write(data)),
        );
        let progress = replayer
            .on_ordered(
                echo,
                Duration::ZERO,
                fixture.backing.as_ref(),
                &EchoData(b"hello".to_vec()),
            )
            .unwrap();
        assert_eq!(progress.applied, Seq(2));
        assert!(fixture.pending.is_empty());
        assert_eq!(replayer.read_state().resolve("/f").unwrap(), id);
    }

    /// 41 §3.2: metadata operations encode class, path and arguments.
    #[test]
    fn u_fuse_meta_body_is_wcp() {
        let fixture = fixture();
        let attr = BackingStore::getattr(fixture.backing.as_ref(), InodeId::ROOT).unwrap();
        let admission = fixture.path.admit(0).unwrap();
        let op_id = admission.op_id;
        fixture
            .path
            .commit_meta(
                admission,
                OpClass::MKDIR,
                None,
                "/d".to_string(),
                MetaArgs::Mode(0o755),
                MetaOwner::from_attr(&attr),
            )
            .unwrap();
        let queued = fixture.outbox.take_ready().unwrap();
        let LocalOp::Meta { class, body, .. } = queued.op else {
            panic!("expected a metadata operation");
        };
        assert_eq!(class, OpClass::MKDIR);
        let fields =
            crate::protocol::messages::FieldMap::parse(&body, &Default::default()).unwrap();
        assert_eq!(
            fields.u8(fid::F_OP_CLASS).unwrap(),
            Some(OpClass::MKDIR.get())
        );
        assert_eq!(fields.str(fid::F_PATH).unwrap(), Some("/d"));
        assert_eq!(fields.u32(fid::F_MODE).unwrap(), Some(0o755));
        assert_eq!(
            fields.fixed::<16>(fid::F_OP_ID).unwrap(),
            Some(op_id.to_bytes())
        );
    }

    /// 41 §3.2: `op_id` is `(instance, local_seq)` in little endian.
    #[test]
    fn u_fuse_op_id_layout() {
        let op_id = op_id_for(InstanceId(0x0102_0304_0506_0708), LocalSeq(9));
        let mut expected = [0u8; 16];
        expected[..8].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        expected[8..].copy_from_slice(&9u64.to_le_bytes());
        assert_eq!(op_id.to_bytes(), expected);
    }

    struct EchoData(Vec<u8>);

    impl crate::client::OpData for EchoData {
        fn read(&self, _data: &DataRef) -> Result<Vec<u8>, Errno> {
            Ok(self.0.clone())
        }
    }
}
