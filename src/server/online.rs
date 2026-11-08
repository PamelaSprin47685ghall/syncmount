//! Online table, session state, watermark and the per-session outbound queue.
//!
//! The table is keyed by the server-assigned `SessionId`, never by address:
//! NAT rebinding and Wi-Fi roaming produce a new connection, not a new
//! identity. `PeerId` is a diagnostic handle and appears in logs only; no
//! branch reads it.
//!
//! # Watermarks
//!
//! [`Watermark::observe`] owns exactly two of the kick criteria: T2
//! (regression) and T3 (overclaim). The lag threshold belongs to the health
//! monitor (W10), which reads the same state for diagnostics only. Splitting
//! them here keeps the sequencer free of duration arithmetic and makes T2/T3
//! testable without a clock.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::protocol::{KickReason, Seq, SessionId};
use crate::transport::PeerId;

use super::config::OutboxConfig;

/// Lifecycle of one attached session (42 §4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SessionState {
    /// Authenticated and catching up from the event log. Live broadcasts are
    /// withheld so replay and live frames cannot interleave.
    Replaying,
    /// Caught up; the session receives broadcasts.
    Online,
    /// Removed from the broadcast set; the writer drains and closes.
    Kicking,
}

impl SessionState {
    /// Whether a session in this state participates in fan-out.
    ///
    /// `Kicking` is the only exclusion: the whole point of the state is that
    /// no `ORDERED` frame follows the `KICK` (42 I9).
    pub const fn receives_broadcast(self) -> bool {
        matches!(self, Self::Online)
    }
}

/// An overflowing queue that keeps draining is slow, not stuck.
///
/// The actor uses this grace to tell backpressure from a dead consumer: an
/// overflow only ends a session when no frame left the queue for this long.
pub const DRAIN_GRACE: Duration = Duration::from_secs(5);

/// Counters shared by the actor and one session writer.
#[derive(Debug)]
pub struct QueueStats {
    frames: AtomicU32,
    bytes: AtomicU64,
    /// Monotonic millis of the last frame handed to the socket.
    last_drain_ms: AtomicU64,
}

impl QueueStats {
    /// Fresh counters; the drain clock starts now, not at process start.
    pub fn new() -> Self {
        Self {
            frames: AtomicU32::new(0),
            bytes: AtomicU64::new(0),
            last_drain_ms: AtomicU64::new(now_millis()),
        }
    }

    /// Queued data frames.
    pub fn frames(&self) -> u32 {
        self.frames.load(Ordering::Relaxed)
    }

    /// Queued data bytes.
    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// Account one enqueued data frame.
    pub fn add(&self, len: usize) {
        self.frames.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(len as u64, Ordering::Relaxed);
    }

    /// Account one frame handed to the socket.
    ///
    /// Both subtractions saturate: a writer that observed a frame the actor
    /// never counted must not wrap a counter.
    pub fn sub(&self, len: usize) {
        self.mark_drain();
        let _ = self
            .frames
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(1))
            });
        let _ = self
            .bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(len as u64))
            });
    }

    /// Record that the writer took a frame off the queue.
    ///
    /// Separated from [`Self::sub`] so a caller can mark progress without
    /// pretending a frame was counted.
    pub fn mark_drain(&self) {
        self.last_drain_ms.store(now_millis(), Ordering::Relaxed);
    }

    /// Time since the writer last took a frame off this queue.
    ///
    /// A queue that never drained since construction reports its age.
    pub fn since_drain(&self) -> Duration {
        Duration::from_millis(
            now_millis().saturating_sub(self.last_drain_ms.load(Ordering::Relaxed)),
        )
    }

    /// Time since the writer last took a frame off this queue, at `now`.
    ///
    /// The actor's tick carries its own clock; tests drive that clock forward
    /// instead of waiting in real time.
    pub fn since_drain_at(&self, now: Instant) -> Duration {
        let now_ms = u64::try_from(now.saturating_duration_since(queue_origin()).as_millis())
            .unwrap_or(u64::MAX);
        Duration::from_millis(now_ms.saturating_sub(self.last_drain_ms.load(Ordering::Relaxed)))
    }
}

impl Default for QueueStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Monotonic origin shared by every queue clock.
fn queue_origin() -> Instant {
    static ORIGIN: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);
    *ORIGIN
}

/// Monotonic millis since the first queue was built.
fn now_millis() -> u64 {
    u64::try_from(queue_origin().elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// What happened when the actor tried to enqueue one frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushOutcome {
    /// Accepted into the bounded channel.
    Queued,
    /// The session exceeded its byte or frame budget.
    Overflow,
    /// The writer is gone; the session is dead.
    Closed,
}

/// Downlink half of one session: one queue for data, one for control.
///
/// Control frames are small, rare and urgent (`WELCOME`, `PONG`, `KICK`,
/// `ERROR`), so they get their own channel and bypass the data budget. Data
/// frames are `ORDERED` broadcasts and relayed ciphertext, counted against
/// the hard 8 MiB ceiling (42 §3.3).
#[derive(Debug)]
pub struct Outbox {
    /// Data channel.
    pub data: mpsc::Sender<Bytes>,
    /// Control channel.
    pub ctrl: mpsc::Sender<Bytes>,
    /// Data queue accounting.
    pub queued: Arc<QueueStats>,
    /// Hard byte ceiling.
    pub cap_bytes: u64,
    /// Hard frame ceiling.
    pub cap_frames: u32,
}

impl Outbox {
    /// Create the channel pair and return the two receivers for the writer.
    pub fn new(config: &OutboxConfig) -> (Self, mpsc::Receiver<Bytes>, mpsc::Receiver<Bytes>) {
        let (data, data_rx) = mpsc::channel(config.data_frames.max(1));
        let (ctrl, ctrl_rx) = mpsc::channel(config.ctrl_frames.max(1));
        (
            Self {
                data,
                ctrl,
                queued: Arc::new(QueueStats::default()),
                cap_bytes: config.cap_bytes,
                cap_frames: config.cap_frames.max(1),
            },
            data_rx,
            ctrl_rx,
        )
    }

    /// Try to enqueue one data frame against the hard budget.
    pub fn try_push_data(&self, frame: Bytes) -> PushOutcome {
        let len = frame.len() as u64;
        if self.queued.bytes() + len > self.cap_bytes || self.queued.frames() >= self.cap_frames {
            return PushOutcome::Overflow;
        }
        match self.data.try_send(frame) {
            Ok(()) => {
                self.queued.add(len as usize);
                PushOutcome::Queued
            }
            Err(mpsc::error::TrySendError::Full(_)) => PushOutcome::Overflow,
            Err(mpsc::error::TrySendError::Closed(_)) => PushOutcome::Closed,
        }
    }

    /// Enqueue one data frame with backpressure.
    ///
    /// Replay uses this path: the actor must not block, and the bounded
    /// channel already caps memory. The frame is charged to the queue
    /// counters so `healthz` and the overflow policy still see it.
    pub async fn send_data(&self, frame: Bytes) -> bool {
        let len = frame.len();
        if self.data.send(frame).await.is_err() {
            return false;
        }
        self.queued.add(len);
        true
    }

    /// Try to enqueue one control frame.
    ///
    /// Control frames are not charged to the data budget: a `KICK` must still
    /// fit when the data queue is exactly at its ceiling.
    pub fn try_push_ctrl(&self, frame: Bytes) -> PushOutcome {
        match self.ctrl.try_send(frame) {
            Ok(()) => PushOutcome::Queued,
            Err(mpsc::error::TrySendError::Full(_)) => PushOutcome::Overflow,
            Err(mpsc::error::TrySendError::Closed(_)) => PushOutcome::Closed,
        }
    }
}

/// Recent client-reported RTT samples.
///
/// The server cannot measure RTT itself: `PING.client_time` is sealed and
/// `PONG.server_time` is only useful to the client (42 D8). The ring holds
/// what the client reports; an empty ring means "unknown".
#[derive(Clone, Copy, Debug)]
pub struct RttRing {
    samples: [u16; Self::CAPACITY],
    len: usize,
    next: usize,
}

impl RttRing {
    /// Window size frozen by 42 §6.1.
    pub const CAPACITY: usize = 60;

    /// Empty ring.
    pub const fn new() -> Self {
        Self {
            samples: [0; Self::CAPACITY],
            len: 0,
            next: 0,
        }
    }

    /// Add one sample, evicting the oldest when full.
    pub fn push(&mut self, rtt_ms: u16) {
        self.samples[self.next] = rtt_ms;
        self.next = (self.next + 1) % Self::CAPACITY;
        self.len = (self.len + 1).min(Self::CAPACITY);
    }

    /// Number of samples held.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether no sample has been reported.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Nearest-rank P99, or `None` for an empty ring.
    pub fn p99(&self) -> Option<u16> {
        if self.len == 0 {
            return None;
        }
        let mut sorted = self.samples;
        sorted[..self.len].sort_unstable();
        let rank = (self.len * 99).div_ceil(100).max(1);
        Some(sorted[rank - 1])
    }
}

impl Default for RttRing {
    fn default() -> Self {
        Self::new()
    }
}

/// The verdict of one watermark observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatermarkVerdict {
    /// Same sequence as before; nothing changed.
    Unchanged,
    /// The client advanced its applied sequence.
    Advanced,
    /// The client reported a different epoch; no watermark update is valid.
    EpochMismatch,
    /// A rule violation that must kick the session.
    Kick(KickReason),
}

/// Monotonic applied-sequence tracking for one session.
#[derive(Clone, Copy, Debug)]
pub struct Watermark {
    applied_seq: Seq,
    last_advance_at: Instant,
    last_work_at: Instant,
    epoch_seen: u64,
    rtt: RttRing,
}

impl Watermark {
    /// Initial watermark from the `HELLO` control prefix.
    pub fn new(applied_seq: Seq, epoch_seen: u64, at: Instant) -> Self {
        Self {
            applied_seq,
            last_advance_at: at,
            last_work_at: at,
            epoch_seen,
            rtt: RttRing::new(),
        }
    }

    /// Highest sequence the client reported applying.
    pub const fn applied_seq(&self) -> Seq {
        self.applied_seq
    }

    /// When the watermark last advanced.
    pub const fn last_advance_at(&self) -> Instant {
        self.last_advance_at
    }

    /// When the oldest still-outstanding operation was sequenced.
    ///
    /// The lag clock starts here when work appears, not at the previous tick:
    /// an operation sequenced a moment before a tick must still get its whole
    /// threshold before it can be reported as lagging.
    pub const fn last_work_at(&self) -> Instant {
        self.last_work_at
    }

    /// Epoch the client reported last.
    pub const fn epoch_seen(&self) -> u64 {
        self.epoch_seen
    }

    /// Reported RTT samples.
    pub const fn rtt(&self) -> &RttRing {
        &self.rtt
    }

    /// Record one RTT sample.
    pub fn push_rtt(&mut self, rtt_ms: u16) {
        self.rtt.push(rtt_ms);
    }

    /// Restart the lag clock because the session has no outstanding work.
    ///
    /// The health monitor calls this from its tick; keeping the clock here
    /// means there is still exactly one source of truth per session.
    pub fn note_idle(&mut self, at: Instant) {
        self.last_advance_at = at;
    }

    /// Restart the lag clock because the server assigned this session new
    /// work.
    ///
    /// The caller sets it only when the session was caught up before the new
    /// operation. An operation that arrives behind an already-outstanding one
    /// must not extend the clock, or a stuck client would hide its lag
    /// while its peers keep writing.
    pub fn note_work(&mut self, at: Instant) {
        self.last_work_at = at;
    }

    /// Apply one observation.
    ///
    /// Order matters and is the one frozen by 42 §4.3: epoch first, then
    /// overclaim, then regression. A report from another epoch says nothing
    /// about this epoch's ordering, so it is never compared.
    pub fn observe(
        &mut self,
        applied: Seq,
        epoch_seen: u64,
        epoch: u64,
        current: Seq,
        at: Instant,
    ) -> WatermarkVerdict {
        if epoch_seen != epoch {
            return WatermarkVerdict::EpochMismatch;
        }
        if applied > current {
            return WatermarkVerdict::Kick(KickReason::Overclaim);
        }
        if applied < self.applied_seq {
            return WatermarkVerdict::Kick(KickReason::Regression);
        }
        if applied == self.applied_seq {
            return WatermarkVerdict::Unchanged;
        }
        self.applied_seq = applied;
        self.last_advance_at = at;
        self.epoch_seen = epoch_seen;
        WatermarkVerdict::Advanced
    }
}

/// Everything needed to construct a [`Session`].
#[derive(Debug)]
pub struct SessionInit {
    /// Server-assigned connection identity.
    pub session_id: SessionId,
    /// Pairing token of the two HTTP halves.
    pub nonce: u64,
    /// Diagnostic connection handle.
    pub peer: PeerId,
    /// Downlink queues.
    pub outbox: Outbox,
    /// Current server epoch.
    pub epoch: u64,
    /// Epoch reported by the client.
    pub epoch_seen: u64,
    /// Applied sequence reported by the client.
    pub applied_seq: Seq,
    /// Current server sequence at attach time.
    pub current_seq: Seq,
    /// Attach instant.
    pub now: Instant,
}

/// One attached session.
///
/// No address field: identity is the server-assigned `session_id`, and a
/// diagnostic `PeerId` is the only connection-shaped value the server keeps.
#[derive(Debug)]
pub struct Session {
    /// Server-assigned connection identity.
    pub session_id: SessionId,
    /// Connection generation assigned by the sequencer at attach.
    ///
    /// A detach names the generation it belongs to, so a late detach from a
    /// replaced connection cannot remove its successor (T4 handoff).
    pub generation: u64,
    /// Pairing token.
    pub nonce: u64,
    /// Diagnostic connection handle.
    pub peer: PeerId,
    /// Lifecycle state.
    pub state: SessionState,
    /// Downlink queues.
    pub outbox: Outbox,
    /// Applied-sequence tracking.
    pub watermark: Watermark,
    /// Attach instant.
    pub opened_at: Instant,
    /// Last valid uplink frame instant: `HELLO`, `PING`, `ORDERED`, relay,
    /// `ACK` or `RESPONSE`. Diagnostic only; liveness comes from the
    /// connection and the kernel keepalive.
    pub last_seen_at: Instant,
    /// Highest sequence enqueued for this session.
    pub last_good_seq: Seq,
}

impl Session {
    /// Build a session from a validated `HELLO`.
    ///
    /// A client from another epoch has no valid watermark here; its applied
    /// sequence is reset to "unsequenced" so the next same-epoch report is
    /// not compared against a value from a different history (42 §4.3).
    pub fn new(init: SessionInit) -> Self {
        let applied = if init.epoch_seen == init.epoch {
            init.applied_seq
        } else {
            Seq::UNSEQUENCED
        };
        Self {
            session_id: init.session_id,
            // The actor overwrites this at attach. Using the pairing nonce as
            // the default keeps direct constructors (tests) distinct.
            generation: init.nonce,
            nonce: init.nonce,
            peer: init.peer,
            state: SessionState::Replaying,
            outbox: init.outbox,
            watermark: Watermark::new(applied, init.epoch_seen, init.now),
            opened_at: init.now,
            last_seen_at: init.now,
            last_good_seq: init.current_seq,
        }
    }
}

/// Sessions keyed by identity, with a nonce index for handshake pairing.
///
/// The table is written only by the sequencer actor. Readers outside the
/// actor use the atomic mirrors in [`super::sequencer::Metrics`].
#[derive(Debug, Default)]
pub struct OnlineTable {
    by_session: HashMap<SessionId, Session>,
    by_nonce: HashMap<u64, SessionId>,
}

impl OnlineTable {
    /// Empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a session, returning the one it replaced.
    ///
    /// The caller decides what a replacement means (T4 kicks the old one
    /// before attaching the new one); the table only keeps both indices
    /// consistent.
    pub fn insert(&mut self, session: Session) -> Option<Session> {
        let old = self.by_session.remove(&session.session_id);
        if let Some(old) = &old {
            self.by_nonce.remove(&old.nonce);
        }
        self.by_nonce.insert(session.nonce, session.session_id);
        self.by_session.insert(session.session_id, session);
        old
    }

    /// Remove one session and its nonce index.
    pub fn remove(&mut self, session_id: &SessionId) -> Option<Session> {
        let session = self.by_session.remove(session_id)?;
        self.by_nonce.remove(&session.nonce);
        Some(session)
    }

    /// Remove one session only when it still carries `generation`.
    ///
    /// A detach from a replaced connection names the old generation and
    /// leaves the successor untouched.
    pub fn remove_generation(
        &mut self,
        session_id: &SessionId,
        generation: u64,
    ) -> Option<Session> {
        if self.by_session.get(session_id)?.generation != generation {
            return None;
        }
        self.remove(session_id)
    }

    /// Whether an identity is attached.
    pub fn contains(&self, session_id: &SessionId) -> bool {
        self.by_session.contains_key(session_id)
    }

    /// Whether a nonce already belongs to an attached session.
    pub fn contains_nonce(&self, nonce: u64) -> bool {
        self.by_nonce.contains_key(&nonce)
    }

    /// Resolve a nonce to its attached identity.
    pub fn nonce_of(&self, nonce: u64) -> Option<SessionId> {
        self.by_nonce.get(&nonce).copied()
    }

    /// Borrow one session.
    pub fn get(&self, session_id: &SessionId) -> Option<&Session> {
        self.by_session.get(session_id)
    }

    /// Mutably borrow one session.
    pub fn get_mut(&mut self, session_id: &SessionId) -> Option<&mut Session> {
        self.by_session.get_mut(session_id)
    }

    /// Iterate every attached session.
    pub fn iter(&self) -> impl Iterator<Item = (&SessionId, &Session)> {
        self.by_session.iter()
    }

    /// Iterate every attached session mutably.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&SessionId, &mut Session)> {
        self.by_session.iter_mut()
    }

    /// Number of attached sessions.
    pub fn len(&self) -> usize {
        self.by_session.len()
    }

    /// Whether no session is attached.
    pub fn is_empty(&self) -> bool {
        self.by_session.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::time::Duration;

    fn instant(seconds: u64) -> Instant {
        Instant::now() + Duration::from_secs(seconds)
    }

    fn session_id(byte: u8) -> SessionId {
        SessionId(u128::from_le_bytes([byte; 16]))
    }

    fn session(id: SessionId, nonce: u64) -> Session {
        let (outbox, _data, _ctrl) = Outbox::new(&OutboxConfig::default());
        Session::new(SessionInit {
            session_id: id,
            nonce,
            peer: PeerId::from_serial(nonce),
            outbox,
            epoch: 7,
            epoch_seen: 7,
            applied_seq: Seq::UNSEQUENCED,
            current_seq: Seq::UNSEQUENCED,
            now: instant(0),
        })
    }

    #[test]
    fn server_watermark_accepts_monotonic_advance() {
        let start = Instant::now();
        let first = start + Duration::from_secs(1);
        let second = start + Duration::from_secs(2);
        let mut watermark = Watermark::new(Seq(0), 7, start);
        assert_eq!(
            watermark.observe(Seq(3), 7, 7, Seq(10), first),
            WatermarkVerdict::Advanced
        );
        assert_eq!(watermark.applied_seq(), Seq(3));
        assert_eq!(watermark.last_advance_at(), first);
        assert_eq!(
            watermark.observe(Seq(3), 7, 7, Seq(10), second),
            WatermarkVerdict::Unchanged
        );
    }

    #[test]
    fn server_watermark_kicks_regression_and_overclaim() {
        let mut watermark = Watermark::new(Seq(5), 7, instant(0));
        assert_eq!(
            watermark.observe(Seq(4), 7, 7, Seq(10), instant(1)),
            WatermarkVerdict::Kick(KickReason::Regression)
        );
        assert_eq!(
            watermark.observe(Seq(11), 7, 7, Seq(10), instant(1)),
            WatermarkVerdict::Kick(KickReason::Overclaim)
        );
        assert_eq!(watermark.applied_seq(), Seq(5));
    }

    #[test]
    fn server_watermark_ignores_other_epoch() {
        let mut watermark = Watermark::new(Seq(5), 6, instant(0));
        assert_eq!(
            watermark.observe(Seq(1), 6, 7, Seq(10), instant(1)),
            WatermarkVerdict::EpochMismatch
        );
        assert_eq!(watermark.applied_seq(), Seq(5));
    }

    #[test]
    fn server_rtt_ring_keeps_a_bounded_window() {
        let mut ring = RttRing::new();
        assert_eq!(ring.p99(), None);
        for sample in 1..=100_u16 {
            ring.push(sample);
        }
        assert_eq!(ring.len(), RttRing::CAPACITY);
        assert_eq!(ring.p99(), Some(100));
    }

    #[test]
    fn server_outbox_enforces_the_byte_ceiling() {
        let config = OutboxConfig {
            cap_bytes: 8,
            cap_frames: 4,
            data_frames: 8,
            ctrl_frames: 2,
        };
        let (outbox, _data, _ctrl) = Outbox::new(&config);
        assert_eq!(
            outbox.try_push_data(Bytes::from_static(b"12345")),
            PushOutcome::Queued
        );
        assert_eq!(outbox.queued.bytes(), 5);
        assert_eq!(
            outbox.try_push_data(Bytes::from_static(b"6789")),
            PushOutcome::Overflow
        );
        assert_eq!(outbox.queued.frames(), 1);
    }

    #[test]
    fn server_online_table_reindexes_replacement() {
        let mut table = OnlineTable::new();
        assert!(table.insert(session(session_id(1), 10)).is_none());
        let old = table.insert(session(session_id(1), 11));
        assert!(old.is_some());
        assert!(!table.contains_nonce(10));
        assert!(table.contains_nonce(11));
        assert_eq!(table.len(), 1);
        assert!(table.remove(&session_id(1)).is_some());
        assert!(table.is_empty());
    }
}
