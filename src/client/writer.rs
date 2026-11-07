//! Unbounded outbox and write coalescer.
//!
//! Owner: W11 (E5). See 41 §2.4/§2.5 and 53 W11.
//!
//! Two independent machines live here:
//!
//! * [`Outbox`] is the admission gate. A caller reserves capacity *before* it
//!   touches the disk, allocates a [`LocalSeq`], and commits the operation.
//!   The queue is keyed by `LocalSeq`, so two FUSE threads that commit out of
//!   order still reach the uplink in sequence order. The queue has no hard
//!   ceiling: a write never fails because the network is behind. A soft RSS
//!   budget warns once when it is crossed, but admission continues. An
//!   operation whose local effect failed is abandoned with [`Outbox::skip`],
//!   so its sequence cannot stall every later operation.
//! * [`Coalescer`] is a pure state machine: it merges adjacent writes of one
//!   inode into one wire operation of at most 4 MiB, and releases a partial
//!   aggregate after the 2 ms quiet window (or 5 ms at the latest, or
//!   immediately at 128 KiB).
//!
//! Neither type performs I/O, holds a lock across a syscall, or invents an
//! order of its own. The uplink (W12) drives them.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::client::config::Tuning;
use crate::protocol::frame::OpId;
use crate::protocol::messages::OpClass;
use crate::store::AttrDelta;
use crate::store::node_table::InodeId;

/// A client-local operation number; the right half of an `op_id`.
///
/// Zero is never allocated: [`LocalSeq::FIRST`] is one, so a defaulted value
/// is recognisable as "unset".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalSeq(pub u64);

impl LocalSeq {
    /// First allocated sequence.
    pub const FIRST: Self = Self(1);

    /// Raw value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Next value, or `None` at the ceiling.
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

impl fmt::Display for LocalSeq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A closed interval of local sequence numbers.
///
/// A coalesced wire operation carries the span it covers; the echo path uses
/// it to locate the pending effects that are now confirmed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    /// First covered sequence.
    pub first: LocalSeq,
    /// Last covered sequence.
    pub last: LocalSeq,
}

impl Span {
    /// Build a span; the arguments must be ordered.
    pub fn new(first: LocalSeq, last: LocalSeq) -> Self {
        debug_assert!(first <= last, "span must be ordered: {first} > {last}");
        Self { first, last }
    }

    /// A span holding one operation.
    pub const fn single(seq: LocalSeq) -> Self {
        Self {
            first: seq,
            last: seq,
        }
    }

    /// Whether `seq` lies inside the span.
    pub const fn contains(self, seq: LocalSeq) -> bool {
        seq.0 >= self.first.0 && seq.0 <= self.last.0
    }

    /// Number of covered operations.
    pub const fn count(self) -> u64 {
        self.last.0.saturating_sub(self.first.0).saturating_add(1)
    }
}

/// One local operation awaiting the uplink.
///
/// `Meta` carries an already-encoded operation body: the writer does not
/// interpret metadata operations, it only guarantees their order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalOp {
    /// Write `data` at `off` inside `ino`.
    Write {
        /// Target inode.
        ino: InodeId,
        /// Byte offset.
        off: u64,
        /// Bytes to send.
        data: Vec<u8>,
    },
    /// Truncate `ino` to `size`.
    Truncate {
        /// Target inode.
        ino: InodeId,
        /// New length.
        size: u64,
    },
    /// Change attributes of `ino`.
    SetAttr {
        /// Target inode.
        ino: InodeId,
        /// Attribute delta.
        delta: AttrDelta,
    },
    /// Set or remove one extended attribute.
    Xattr {
        /// Target inode.
        ino: InodeId,
        /// Attribute name.
        name: Vec<u8>,
        /// New value, or `None` to remove.
        value: Option<Vec<u8>>,
    },
    /// A metadata operation, encoded by the caller.
    Meta {
        /// Target inode, when the operation has one.
        ino: Option<InodeId>,
        /// Operation class.
        class: OpClass,
        /// Encoded operation body.
        body: Vec<u8>,
    },
}

impl LocalOp {
    /// The inode this operation touches, if any.
    pub const fn ino(&self) -> Option<InodeId> {
        match self {
            Self::Write { ino, .. }
            | Self::Truncate { ino, .. }
            | Self::SetAttr { ino, .. }
            | Self::Xattr { ino, .. } => Some(*ino),
            Self::Meta { ino, .. } => *ino,
        }
    }

    /// Bytes this operation occupies in the outbox.
    pub fn byte_len(&self) -> usize {
        match self {
            Self::Write { data, .. } => data.len(),
            Self::Xattr { name, value, .. } => name.len() + value.as_ref().map_or(0, Vec::len),
            Self::Meta { body, .. } => body.len(),
            Self::Truncate { .. } | Self::SetAttr { .. } => 0,
        }
    }

    /// Whether this is a data write the coalescer may merge.
    pub const fn is_write(&self) -> bool {
        matches!(self, Self::Write { .. })
    }
}

/// One queued operation, tagged with the sequence it was allocated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedOp {
    /// Allocated sequence.
    pub seq: LocalSeq,
    /// Operation identifier.
    pub op_id: OpId,
    /// Operation payload.
    pub op: LocalOp,
}

impl QueuedOp {
    /// Build a queued operation.
    pub const fn new(seq: LocalSeq, op_id: OpId, op: LocalOp) -> Self {
        Self { seq, op_id, op }
    }
}

/// Current outbox occupancy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OutboxDepth {
    /// Reserved operations, including reservations not yet committed.
    pub ops: usize,
    /// Reserved bytes, including reservations not yet committed.
    pub bytes: usize,
}

/// Replay-backlog window shared by the replayer and the outbox.
///
/// The window counts local operations that were admitted but whose echo has
/// not been applied yet. It is diagnostic only: a closed window never refuses
/// admission and never stops the uplink. Backpressure on the write path is
/// forbidden, because the network must not turn a successful local write into
/// `ENOSPC`.
///
/// A sequence hole is still tracked so status can explain a stalled replay.
/// The two limits give the counter hysteresis: mark closed at `high`, clear
/// at `low`.
#[derive(Debug)]
pub struct Backpressure {
    in_flight: AtomicUsize,
    high: usize,
    low: usize,
    closed: AtomicBool,
    gap: AtomicBool,
}

impl Backpressure {
    /// Mark the counter closed at `high` operations in flight, clear at `low`.
    pub fn new(high: usize, low: usize) -> Self {
        let high = high.max(1);
        Self {
            in_flight: AtomicUsize::new(0),
            high,
            low: low.min(high - 1),
            closed: AtomicBool::new(false),
            gap: AtomicBool::new(false),
        }
    }

    /// The production thresholds: mark closed at 256 in-flight operations,
    /// clear at 128.
    ///
    /// These numbers only shape the status counter. The outbox no longer
    /// consults them, so a lagging replay cannot fail a local write.
    pub fn default_window() -> Self {
        Self::new(256, 128)
    }

    /// Whether the diagnostic counter is below its low threshold.
    ///
    /// Admission and sending never consult this value.
    pub fn is_open(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
    }

    /// Count one admitted local operation.
    pub fn note_in_flight(&self) {
        let now = self
            .in_flight
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        if now >= self.high {
            self.closed.store(true, Ordering::Release);
        }
    }

    /// Count one applied echo.
    pub fn note_echo(&self) {
        let _ = self
            .in_flight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |in_flight| {
                Some(in_flight.saturating_sub(1))
            });
        if self.in_flight.load(Ordering::Acquire) <= self.low && !self.gap.load(Ordering::Acquire) {
            self.closed.store(false, Ordering::Release);
        }
    }

    /// Mark the counter closed while a sequence hole is open, clear it when
    /// the hole fills.
    pub fn set_gap(&self, gap: bool) {
        self.gap.store(gap, Ordering::Release);
        if gap {
            self.closed.store(true, Ordering::Release);
        } else if self.in_flight.load(Ordering::Acquire) <= self.low {
            self.closed.store(false, Ordering::Release);
        }
    }

    /// Forget every in-flight operation (resync, new session, unmount).
    pub fn reset(&self) {
        self.in_flight.store(0, Ordering::Release);
        self.gap.store(false, Ordering::Release);
        self.closed.store(false, Ordering::Release);
    }

    /// Operations counted as in flight.
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Acquire)
    }
}

/// Unbounded, sequence-ordered admission queue.
///
/// Capacity is counted at [`Outbox::reserve`] time so the soft budget sees an
/// operation before its disk write, but the count is advisory: admission never
/// fails. "Returned success" still means "already admitted" (41 invariant 4).
pub struct Outbox {
    inner: Mutex<OutboxInner>,
    next_seq: AtomicU64,
    soft_bytes: usize,
    soft_ops: usize,
    over_soft: AtomicBool,
    /// Replay counter, for diagnostics only. It never gates admission.
    backpressure: Arc<Backpressure>,
}

struct OutboxInner {
    queue: BTreeMap<LocalSeq, QueuedOp>,
    next_send: LocalSeq,
    reserved_bytes: usize,
    reserved_ops: usize,
    flush_hints: BTreeSet<InodeId>,
    /// Sequences that were allocated and then abandoned. The uplink must
    /// advance past them without sending anything.
    skipped: BTreeSet<LocalSeq>,
}

impl Outbox {
    /// Create an outbox with the given soft budget.
    ///
    /// `soft_bytes` and `soft_ops` only drive a one-shot warning. They never
    /// reject an operation.
    pub fn new(soft_bytes: usize, soft_ops: usize) -> Self {
        Self {
            inner: Mutex::new(OutboxInner {
                queue: BTreeMap::new(),
                next_send: LocalSeq::FIRST,
                reserved_bytes: 0,
                reserved_ops: 0,
                flush_hints: BTreeSet::new(),
                skipped: BTreeSet::new(),
            }),
            next_seq: AtomicU64::new(LocalSeq::FIRST.get()),
            soft_bytes: soft_bytes.max(1),
            soft_ops: soft_ops.max(1),
            over_soft: AtomicBool::new(false),
            backpressure: Arc::new(Backpressure::default_window()),
        }
    }

    /// Create an outbox from the client tuning.
    pub fn with_tuning(tuning: &Tuning) -> Self {
        Self::new(tuning.outbox_soft_bytes, tuning.outbox_soft_ops)
    }

    /// Attach the replay counter the replayer updates.
    ///
    /// The counter is advisory. Attaching it keeps `in_flight` accurate in the
    /// status file; it does not restore admission or send gating.
    pub fn with_backpressure(mut self, backpressure: Arc<Backpressure>) -> Self {
        self.backpressure = backpressure;
        self
    }

    /// Reserve capacity for one operation of `bytes` payload.
    ///
    /// The returned guard releases the capacity on drop unless it is committed.
    /// This call never fails: the network cannot turn a local write into
    /// `ENOSPC`. A real disk error still surfaces from the backing store.
    pub fn reserve(&self, bytes: usize) -> Reservation<'_> {
        let mut inner = self.lock();
        inner.reserved_bytes = inner.reserved_bytes.saturating_add(bytes);
        inner.reserved_ops = inner.reserved_ops.saturating_add(1);
        let over = inner.reserved_bytes > self.soft_bytes || inner.reserved_ops > self.soft_ops;
        let bytes_now = inner.reserved_bytes;
        let ops_now = inner.reserved_ops;
        drop(inner);
        if over && !self.over_soft.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                soft_bytes = self.soft_bytes,
                soft_ops = self.soft_ops,
                queued_bytes = bytes_now,
                queued_ops = ops_now,
                "outbox exceeded its soft budget; writes continue"
            );
        }
        Reservation {
            outbox: self,
            bytes,
            settled: false,
        }
    }

    /// Allocate the next local sequence number.
    pub fn alloc_seq(&self) -> LocalSeq {
        LocalSeq(self.next_seq.fetch_add(1, Ordering::Relaxed))
    }

    /// The sequence the uplink must send next.
    pub fn next_send(&self) -> LocalSeq {
        self.lock().next_send
    }

    /// Remove and return the next sendable operation.
    ///
    /// Returns `None` while the queue has a hole at `next_send`: the uplink
    /// must never reorder operations, so it waits for the missing sequence.
    /// A sequence whose local operation failed is abandoned with
    /// [`Outbox::skip`], which closes the hole without sending anything.
    pub fn take_ready(&self) -> Option<QueuedOp> {
        let mut inner = self.lock();
        loop {
            let seq = inner.next_send;
            if inner.skipped.remove(&seq) {
                inner.next_send = seq.checked_next().unwrap_or(seq);
                continue;
            }
            let queued = inner.queue.remove(&seq)?;
            inner.reserved_bytes = inner.reserved_bytes.saturating_sub(queued.op.byte_len());
            inner.reserved_ops = inner.reserved_ops.saturating_sub(1);
            inner.next_send = seq.checked_next().unwrap_or(seq);
            self.clear_soft_alert(&inner);
            // Count the operation only when it leaves for the wire. An
            // operation still queued behind a sequence hole must not hold the
            // replay counter shut after every sent operation has been echoed.
            if !matches!(queued.op, LocalOp::Xattr { .. }) {
                self.backpressure.note_in_flight();
            }
            return Some(queued);
        }
    }

    /// Whether an operation is queued at the first non-skipped sequence.
    pub fn has_ready(&self) -> bool {
        let inner = self.lock();
        let mut seq = inner.next_send;
        loop {
            if inner.skipped.contains(&seq) {
                let Some(next) = seq.checked_next() else {
                    return false;
                };
                seq = next;
                continue;
            }
            return inner.queue.contains_key(&seq);
        }
    }

    /// Abandon one allocated sequence.
    ///
    /// The reservation must already have been aborted. The uplink advances
    /// past `seq` without sending it, so a failed local operation cannot
    /// stall every later operation behind a permanent hole (41 §3.1).
    pub fn skip(&self, seq: LocalSeq) {
        let mut inner = self.lock();
        if seq < inner.next_send {
            return;
        }
        inner.skipped.insert(seq);
    }

    /// Current occupancy.
    pub fn depth(&self) -> OutboxDepth {
        let inner = self.lock();
        OutboxDepth {
            ops: inner.reserved_ops,
            bytes: inner.reserved_bytes,
        }
    }

    /// Ask the uplink to flush everything for `ino` (used by `fsync`).
    pub fn flush_hint(&self, ino: InodeId) {
        self.lock().flush_hints.insert(ino);
    }

    /// Drain the flush hints.
    pub fn take_flush_hints(&self) -> Vec<InodeId> {
        let mut inner = self.lock();
        std::mem::take(&mut inner.flush_hints).into_iter().collect()
    }

    /// Number of queued operations, committed or reserved.
    pub fn len(&self) -> usize {
        self.lock().reserved_ops
    }

    /// Whether nothing is queued or reserved.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn push(&self, seq: LocalSeq, op_id: OpId, op: LocalOp) {
        let mut inner = self.lock();
        if let Some(previous) = inner.queue.insert(seq, QueuedOp::new(seq, op_id, op)) {
            // A duplicate sequence means the caller reused a number; keep the
            // newer payload but do not double-charge the byte budget.
            inner.reserved_bytes = inner.reserved_bytes.saturating_sub(previous.op.byte_len());
        }
    }

    fn release(&self, bytes: usize) {
        let mut inner = self.lock();
        inner.reserved_bytes = inner.reserved_bytes.saturating_sub(bytes);
        inner.reserved_ops = inner.reserved_ops.saturating_sub(1);
        self.clear_soft_alert(&inner);
    }

    fn clear_soft_alert(&self, inner: &OutboxInner) {
        if inner.reserved_bytes <= self.soft_bytes && inner.reserved_ops <= self.soft_ops {
            self.over_soft.store(false, Ordering::Relaxed);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, OutboxInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl fmt::Debug for Outbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let depth = self.depth();
        f.debug_struct("Outbox")
            .field("ops", &depth.ops)
            .field("bytes", &depth.bytes)
            .field("soft_ops", &self.soft_ops)
            .field("soft_bytes", &self.soft_bytes)
            .finish()
    }
}

/// Admission ticket returned by [`Outbox::reserve`].
///
/// Dropping an uncommitted ticket returns the capacity; this is what makes an
/// early `?` in the write path safe.
pub struct Reservation<'a> {
    outbox: &'a Outbox,
    bytes: usize,
    settled: bool,
}

impl Reservation<'_> {
    /// Commit the operation. The capacity stays charged until the uplink sends
    /// it.
    pub fn commit(mut self, seq: LocalSeq, op_id: OpId, op: LocalOp) {
        self.settled = true;
        self.outbox.push(seq, op_id, op);
    }

    /// Drop the operation and return the capacity.
    pub fn abort(mut self) {
        self.settled = true;
        self.outbox.release(self.bytes);
    }

    /// Bytes this reservation holds.
    pub const fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.outbox.release(self.bytes);
        }
    }
}

impl fmt::Debug for Reservation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reservation")
            .field("bytes", &self.bytes)
            .field("settled", &self.settled)
            .finish()
    }
}

/// Coalescer limits, decoupled from [`Tuning`] so the state machine stays a
/// pure function of its inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoalesceTuning {
    /// Size that forces an immediate send.
    pub aggregate_bytes: usize,
    /// Quiet window for a partial aggregate.
    pub window: Duration,
    /// Hard age ceiling for a partial aggregate.
    pub hard: Duration,
    /// Largest aggregate the coalescer will build.
    pub max_aggregate: usize,
}

impl Default for CoalesceTuning {
    fn default() -> Self {
        Self::from(&Tuning::default())
    }
}

impl From<&Tuning> for CoalesceTuning {
    fn from(tuning: &Tuning) -> Self {
        Self {
            aggregate_bytes: tuning.aggregate_bytes,
            window: tuning.aggregate_window,
            hard: tuning.aggregate_hard,
            max_aggregate: tuning.aggregate_max,
        }
    }
}

/// One aggregate ready for the uplink.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireOp {
    /// Covered local sequences.
    pub span: Span,
    /// Operation id of the first covered write.
    ///
    /// The aggregate is signed and echoed as this one operation; the span
    /// tells the echo path which pending effects it confirms.
    pub op_id: OpId,
    /// Target inode.
    pub ino: InodeId,
    /// Offset of the first byte.
    pub off: u64,
    /// Aggregated bytes.
    pub data: Vec<u8>,
}

impl WireOp {
    /// Byte length.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the aggregate carries no data.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// The coalescer cannot merge this operation.
///
/// The uplink must flush the current aggregate first, then send the operation
/// on its own; doing so preserves the sequence order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotCoalescable;

impl fmt::Display for NotCoalescable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("operation cannot be coalesced")
    }
}

impl std::error::Error for NotCoalescable {}

#[derive(Debug)]
struct Batch {
    span: Span,
    op_id: OpId,
    ino: InodeId,
    off: u64,
    end: u64,
    data: Vec<u8>,
    first_at: Duration,
    last_push: Duration,
}

impl Batch {
    fn new(queued: &QueuedOp, ino: InodeId, off: u64, data: &[u8], now: Duration) -> Self {
        Self {
            span: Span::single(queued.seq),
            op_id: queued.op_id,
            ino,
            off,
            end: off.saturating_add(data.len() as u64),
            data: data.to_vec(),
            first_at: now,
            last_push: now,
        }
    }

    fn can_absorb(
        &self,
        queued: &QueuedOp,
        ino: InodeId,
        off: u64,
        len: usize,
        max: usize,
    ) -> bool {
        let adjacent = self.span.last.checked_next() == Some(queued.seq);
        adjacent && self.ino == ino && self.end == off && self.data.len().saturating_add(len) <= max
    }

    fn absorb(&mut self, queued: &QueuedOp, off: u64, data: &[u8], now: Duration) {
        debug_assert_eq!(self.end, off);
        self.data.extend_from_slice(data);
        self.end = off.saturating_add(data.len() as u64);
        self.span.last = queued.seq;
        self.last_push = now;
    }

    fn wire(&self) -> WireOp {
        WireOp {
            span: self.span,
            op_id: self.op_id,
            ino: self.ino,
            off: self.off,
            data: self.data.clone(),
        }
    }
}

/// Pure write-aggregation state machine.
#[derive(Debug)]
pub struct Coalescer {
    batch: Option<Batch>,
    tuning: CoalesceTuning,
}

impl Coalescer {
    /// Create a coalescer with the given limits.
    pub const fn new(tuning: CoalesceTuning) -> Self {
        Self {
            batch: None,
            tuning,
        }
    }

    /// Create a coalescer from the client tuning.
    pub fn with_tuning(tuning: &Tuning) -> Self {
        Self::new(CoalesceTuning::from(tuning))
    }

    /// Offer one queued operation.
    ///
    /// Returns `Ok(Some(op))` when an aggregate must be sent now, `Ok(None)`
    /// when the operation was absorbed and may still grow, and
    /// [`NotCoalescable`] for anything that is not an adjacent write of the
    /// same inode. In the last case the caller flushes with
    /// [`Coalescer::flush_all`] and sends the operation itself.
    pub fn push(
        &mut self,
        queued: &QueuedOp,
        now: Duration,
    ) -> Result<Option<WireOp>, NotCoalescable> {
        let LocalOp::Write { ino, off, data } = &queued.op else {
            return Err(NotCoalescable);
        };
        let ino = *ino;
        let off = *off;

        let fits = self.batch.as_ref().is_some_and(|batch| {
            batch.can_absorb(queued, ino, off, data.len(), self.tuning.max_aggregate)
        });
        if fits {
            let Some(batch) = self.batch.as_mut() else {
                return Ok(None);
            };
            batch.absorb(queued, off, data, now);
            if batch.data.len() >= self.tuning.aggregate_bytes {
                return Ok(self.take());
            }
            return Ok(None);
        }

        let previous = self.take();
        self.batch = Some(Batch::new(queued, ino, off, data, now));
        // Only release the fresh batch immediately when nothing else is
        // waiting to be sent; otherwise the caller sends `previous` first and
        // the fresh batch is released on the next call, preserving order.
        if previous.is_none()
            && self
                .batch
                .as_ref()
                .is_some_and(|batch| batch.data.len() >= self.tuning.aggregate_bytes)
        {
            let current = self.take();
            return Ok(current);
        }
        Ok(previous)
    }

    /// Release the aggregate if it is due.
    pub fn due(&mut self, now: Duration) -> Option<WireOp> {
        let batch = self.batch.as_ref()?;
        let age = now.saturating_sub(batch.first_at);
        let idle = now.saturating_sub(batch.last_push);
        if age >= self.tuning.hard || (age >= self.tuning.window && idle >= self.tuning.window) {
            return self.take();
        }
        None
    }

    /// Release the aggregate if it belongs to `ino` (`fsync` path).
    pub fn flush_inode(&mut self, ino: InodeId) -> Option<WireOp> {
        if self.batch.as_ref().is_some_and(|batch| batch.ino == ino) {
            return self.take();
        }
        None
    }

    /// Release whatever is buffered.
    pub fn flush_all(&mut self) -> Option<WireOp> {
        self.take()
    }

    /// Whether an aggregate is buffered.
    pub fn is_empty(&self) -> bool {
        self.batch.is_none()
    }

    /// Bytes currently buffered.
    pub fn buffered_bytes(&self) -> usize {
        self.batch.as_ref().map_or(0, |batch| batch.data.len())
    }

    fn take(&mut self) -> Option<WireOp> {
        self.batch.take().map(|batch| batch.wire())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn op_id(seed: u8) -> OpId {
        OpId::from_bytes([seed; 16])
    }

    fn write(ino: u128, off: u64, data: &[u8]) -> LocalOp {
        LocalOp::Write {
            ino: InodeId(ino),
            off,
            data: data.to_vec(),
        }
    }

    fn queued(seq: u64, ino: u128, off: u64, data: &[u8]) -> QueuedOp {
        QueuedOp::new(LocalSeq(seq), op_id(seq as u8), write(ino, off, data))
    }

    /// 41 §2.4, INV-04: capacity precedes the disk write.
    #[test]
    fn u_writer_outbox_reserve_commit_and_depth() {
        let outbox = Outbox::new(1024, 8);
        assert!(outbox.is_empty());
        let seq = outbox.alloc_seq();
        assert_eq!(seq, LocalSeq::FIRST);

        let reservation = outbox.reserve(100);
        assert_eq!(outbox.depth(), OutboxDepth { ops: 1, bytes: 100 });
        reservation.commit(seq, op_id(1), write(1, 0, &[0; 100]));
        assert_eq!(outbox.depth(), OutboxDepth { ops: 1, bytes: 100 });

        let ready = outbox.take_ready().unwrap();
        assert_eq!(ready.seq, LocalSeq::FIRST);
        assert_eq!(ready.op.byte_len(), 100);
        assert!(outbox.is_empty());
        assert!(outbox.take_ready().is_none());
    }

    /// Backpressure is forbidden: crossing the soft budget never rejects an
    /// operation, and a dropped guard still releases its charge.
    #[test]
    fn u_writer_outbox_soft_budget_never_rejects() {
        let outbox = Outbox::new(64, 2);
        let first = outbox.reserve(64);
        // Both budgets are exceeded; admission still succeeds.
        let second = outbox.reserve(1);
        assert_eq!(outbox.depth(), OutboxDepth { ops: 2, bytes: 65 });

        // Dropping the guards releases the reservations.
        drop(second);
        drop(first);
        assert!(outbox.is_empty());

        // The operation budget is advisory too.
        let outbox = Outbox::new(1024, 1);
        let held = outbox.reserve(0);
        let also = outbox.reserve(0);
        assert_eq!(outbox.depth(), OutboxDepth { ops: 2, bytes: 0 });
        held.abort();
        also.abort();
        assert!(outbox.is_empty());
    }

    /// 41 §2.4: concurrent commits still leave in sequence order.
    #[test]
    fn u_writer_outbox_orders_by_sequence() {
        let outbox = Outbox::new(1024, 16);
        let a = outbox.alloc_seq();
        let b = outbox.alloc_seq();
        let c = outbox.alloc_seq();
        assert_eq!((a.get(), b.get(), c.get()), (1, 2, 3));

        // Commit 3, then 1, then 2.
        let r3 = outbox.reserve(1);
        r3.commit(c, op_id(3), write(1, 2, b"c"));
        assert!(outbox.take_ready().is_none(), "a hole must block the queue");
        let r1 = outbox.reserve(1);
        r1.commit(a, op_id(1), write(1, 0, b"a"));
        assert_eq!(outbox.take_ready().unwrap().seq, a);
        let r2 = outbox.reserve(1);
        r2.commit(b, op_id(2), write(1, 1, b"b"));
        assert_eq!(outbox.take_ready().unwrap().seq, b);
        assert_eq!(outbox.take_ready().unwrap().seq, c);
        assert!(outbox.is_empty());
    }

    /// W13b: an abandoned sequence closes its hole without reordering.
    #[test]
    fn u_writer_outbox_skip_closes_hole() {
        let outbox = Outbox::new(1024, 8);
        let a = outbox.alloc_seq();
        let b = outbox.alloc_seq();
        let c = outbox.alloc_seq();

        // The local operation for `b` failed: its capacity is returned and
        // its sequence is abandoned.
        let rb = outbox.reserve(1);
        rb.abort();
        outbox.skip(b);

        // `c` commits before `a`; the queue waits at `a`, then passes `b`.
        let rc = outbox.reserve(1);
        rc.commit(c, op_id(3), write(1, 2, b"c"));
        assert!(outbox.take_ready().is_none());
        let ra = outbox.reserve(1);
        ra.commit(a, op_id(1), write(1, 0, b"a"));
        assert_eq!(outbox.take_ready().unwrap().seq, a);
        assert_eq!(outbox.take_ready().unwrap().seq, c);
        assert!(outbox.take_ready().is_none());
        assert!(!outbox.has_ready());

        // Skipping the sequence at the head also clears `has_ready`.
        let d = outbox.alloc_seq();
        let rd = outbox.reserve(0);
        rd.abort();
        outbox.skip(d);
        assert!(!outbox.has_ready());
    }

    /// 41 §2.4: flush hints are drained once.
    #[test]
    fn u_writer_outbox_flush_hints() {
        let outbox = Outbox::new(1024, 4);
        outbox.flush_hint(InodeId(9));
        outbox.flush_hint(InodeId(9));
        outbox.flush_hint(InodeId(3));
        assert_eq!(outbox.take_flush_hints(), vec![InodeId(3), InodeId(9)]);
        assert!(outbox.take_flush_hints().is_empty());
    }

    /// 41 §2.5: adjacent writes of one inode merge into one wire op.
    #[test]
    fn u_writer_coalescer_merges_adjacent_writes() {
        let mut coalescer = Coalescer::new(CoalesceTuning::default());
        let t0 = Duration::from_millis(10);
        assert!(
            coalescer
                .push(&queued(1, 1, 0, b"aa"), t0)
                .unwrap()
                .is_none()
        );
        assert!(
            coalescer
                .push(&queued(2, 1, 2, b"bb"), t0)
                .unwrap()
                .is_none()
        );
        assert_eq!(coalescer.buffered_bytes(), 4);

        let wire = coalescer.flush_all().unwrap();
        assert_eq!(wire.span, Span::new(LocalSeq(1), LocalSeq(2)));
        assert_eq!(wire.op_id, op_id(1), "the first write signs the aggregate");
        assert_eq!(wire.ino, InodeId(1));
        assert_eq!(wire.off, 0);
        assert_eq!(wire.data, b"aabb");
        assert!(coalescer.is_empty());
    }

    /// 41 §2.5: a hole, another inode, or another class breaks the batch.
    #[test]
    fn u_writer_coalescer_breaks_on_gap_inode_and_class() {
        let t0 = Duration::from_millis(10);
        let mut coalescer = Coalescer::new(CoalesceTuning::default());

        // Sequence hole: 1 then 3.
        coalescer.push(&queued(1, 1, 0, b"aa"), t0).unwrap();
        let first = coalescer
            .push(&queued(3, 1, 2, b"cc"), t0)
            .unwrap()
            .unwrap();
        assert_eq!(first.span, Span::single(LocalSeq(1)));
        assert_eq!(coalescer.buffered_bytes(), 2);
        assert_eq!(
            coalescer.flush_all().unwrap().span,
            Span::single(LocalSeq(3))
        );

        // Different inode.
        coalescer.push(&queued(4, 1, 0, b"aa"), t0).unwrap();
        let other = coalescer
            .push(&queued(5, 2, 2, b"bb"), t0)
            .unwrap()
            .unwrap();
        assert_eq!(other.ino, InodeId(1));
        assert_eq!(coalescer.flush_all().unwrap().ino, InodeId(2));

        // Non-write operations are never coalesced.
        coalescer.push(&queued(6, 1, 0, b"aa"), t0).unwrap();
        let meta = QueuedOp::new(
            LocalSeq(7),
            op_id(7),
            LocalOp::Meta {
                ino: Some(InodeId(1)),
                class: OpClass::MKDIR,
                body: Vec::new(),
            },
        );
        assert_eq!(coalescer.push(&meta, t0), Err(NotCoalescable));
        assert_eq!(
            coalescer.flush_all().unwrap().span,
            Span::single(LocalSeq(6))
        );
    }

    /// 39 §2.1: 128 KiB sends immediately.
    #[test]
    fn u_writer_coalescer_sends_at_128k() {
        let mut coalescer = Coalescer::new(CoalesceTuning::default());
        let t0 = Duration::from_millis(1);
        let chunk = vec![0u8; 64 * 1024];
        assert!(
            coalescer
                .push(&queued(1, 1, 0, &chunk), t0)
                .unwrap()
                .is_none()
        );
        let wire = coalescer
            .push(&queued(2, 1, 64 * 1024, &chunk), t0)
            .unwrap()
            .unwrap();
        assert_eq!(wire.data.len(), 128 * 1024);
        assert_eq!(wire.span, Span::new(LocalSeq(1), LocalSeq(2)));
        assert!(coalescer.is_empty());
    }

    /// 39 §2.1: 2 ms quiet window, 5 ms hard ceiling.
    #[test]
    fn u_writer_coalescer_window_and_hard_ceiling() {
        let mut coalescer = Coalescer::new(CoalesceTuning::default());
        coalescer
            .push(&queued(1, 1, 0, b"aa"), Duration::from_millis(100))
            .unwrap();
        assert!(coalescer.due(Duration::from_micros(100_500)).is_none());
        // Quiet for 2 ms: the partial aggregate is released.
        assert!(coalescer.due(Duration::from_millis(102)).is_some());
        assert!(coalescer.is_empty());

        // A continuous stream is held past the quiet window and released at
        // the hard ceiling.
        coalescer
            .push(&queued(2, 1, 0, b"aa"), Duration::from_millis(200))
            .unwrap();
        coalescer
            .push(&queued(3, 1, 2, b"bb"), Duration::from_millis(202))
            .unwrap();
        assert!(
            coalescer.due(Duration::from_millis(203)).is_none(),
            "age 3 ms < 5 ms hard ceiling"
        );
        let wire = coalescer.due(Duration::from_millis(205)).unwrap();
        assert_eq!(wire.data, b"aabb");
    }

    /// 41 §3.3: fsync flushes only the aggregate of its inode.
    #[test]
    fn u_writer_coalescer_flush_inode() {
        let mut coalescer = Coalescer::new(CoalesceTuning::default());
        let t0 = Duration::from_millis(1);
        coalescer.push(&queued(1, 1, 0, b"aa"), t0).unwrap();
        assert!(coalescer.flush_inode(InodeId(2)).is_none());
        let wire = coalescer.flush_inode(InodeId(1)).unwrap();
        assert_eq!(wire.data, b"aa");
        assert!(coalescer.is_empty());
    }

    /// 41 §2.5: an aggregate never exceeds `max_aggregate`.
    #[test]
    fn u_writer_coalescer_respects_max_aggregate() {
        let tuning = CoalesceTuning {
            aggregate_bytes: usize::MAX,
            max_aggregate: 8,
            ..CoalesceTuning::default()
        };
        let mut coalescer = Coalescer::new(tuning);
        let t0 = Duration::from_millis(1);
        coalescer.push(&queued(1, 1, 0, b"aaaa"), t0).unwrap();
        assert!(
            coalescer
                .push(&queued(2, 1, 4, b"bbbb"), t0)
                .unwrap()
                .is_none(),
            "exactly at the ceiling still fits"
        );
        // The next adjacent write cannot be absorbed: the full aggregate goes
        // out and the new one starts fresh.
        let wire = coalescer
            .push(&queued(3, 1, 8, b"cccc"), t0)
            .unwrap()
            .unwrap();
        assert_eq!(wire.data, b"aaaabbbb");
        assert_eq!(wire.span, Span::new(LocalSeq(1), LocalSeq(2)));
        assert_eq!(coalescer.buffered_bytes(), 4);
    }

    /// The replay counter is diagnostic: a closed window neither refuses
    /// admission nor stops the uplink.
    #[test]
    fn u_writer_backpressure_never_gates_outbox() {
        let window = Arc::new(Backpressure::new(3, 1));
        let outbox = Outbox::new(1024, 8).with_backpressure(Arc::clone(&window));

        let a = outbox.alloc_seq();
        let b = outbox.alloc_seq();
        let c = outbox.alloc_seq();
        outbox.reserve(1).commit(a, op_id(1), write(1, 0, b"a"));
        assert_eq!(window.in_flight(), 0, "a queued op is not on the wire yet");
        assert_eq!(outbox.take_ready().unwrap().seq, a);
        outbox.reserve(1).commit(b, op_id(2), write(1, 1, b"b"));
        assert_eq!(outbox.take_ready().unwrap().seq, b);
        outbox.reserve(1).commit(c, op_id(3), write(1, 2, b"c"));
        assert_eq!(outbox.take_ready().unwrap().seq, c);
        assert_eq!(window.in_flight(), 3);
        assert!(!window.is_open());

        // A closed window still admits and sends; the local write must never
        // fail because the replay is behind.
        let d = outbox.alloc_seq();
        outbox.reserve(1).commit(d, op_id(4), write(1, 3, b"d"));
        assert_eq!(outbox.take_ready().unwrap().seq, d);

        // Hysteresis still tracks the counter for diagnostics.
        window.note_echo();
        assert!(!window.is_open());
        window.note_echo();
        window.note_echo();
        assert!(window.is_open());
    }

    /// A sequence hole is reported, never enforced.
    #[test]
    fn u_writer_backpressure_gap_never_blocks_admission() {
        let window = Arc::new(Backpressure::new(8, 2));
        let outbox = Outbox::new(1024, 8).with_backpressure(Arc::clone(&window));

        window.set_gap(true);
        let held = outbox.reserve(0);
        assert!(!window.is_open());
        drop(held);
        window.set_gap(false);
        assert!(window.is_open());
    }

    /// An xattr has no wire class and never echoes, so it must not hold the
    /// window shut.
    #[test]
    fn u_writer_backpressure_ignores_xattr() {
        let window = Arc::new(Backpressure::new(1, 0));
        let outbox = Outbox::new(1024, 8).with_backpressure(Arc::clone(&window));
        let seq = outbox.alloc_seq();
        outbox.reserve(0).commit(
            seq,
            op_id(1),
            LocalOp::Xattr {
                ino: InodeId(1),
                name: b"user.x".to_vec(),
                value: None,
            },
        );
        assert_eq!(outbox.take_ready().unwrap().seq, seq);
        assert_eq!(window.in_flight(), 0);
        assert!(window.is_open());
    }
}
