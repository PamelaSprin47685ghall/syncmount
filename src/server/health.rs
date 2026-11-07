//! Watermark diagnostics: the dynamic lag threshold and the busy gate.
//!
//! This module never ends a session. It answers one question for the tick:
//! "does this client look behind, and by how much?" The answer feeds logs and
//! metrics. Liveness comes from the TCP connection and the kernel keepalive;
//! a slow client is allowed to stay slow for as long as it keeps making
//! progress.
//!
//! # Threshold
//!
//! ```text
//! threshold = 3 × RTT_p99
//!           + backlog_bytes / 1 MiB/s
//!           + pending_ops × 100 ms
//!           capped at 24 h
//! ```
//!
//! `RTT_p99` is the nearest-rank P99 of the last 60 client-reported samples;
//! an empty ring falls back to the pessimistic 300 ms constant because the
//! server cannot measure RTT itself (42 D8). `backlog_bytes` is the outbox
//! byte count, the only precise "not yet on the socket" number in a
//! window-zero design (42 D11). `pending_ops` is
//! `last_op_seq - applied_seq`, a pure count.
//!
//! # Busy gate
//!
//! The lag clock only runs while the session has an unapplied `ORDERED`. An
//! idle session resets `last_advance_at` to `now` on every tick, so a quiet
//! mount never accumulates lag. A `LEAVE` consumes a sequence but assigns no
//! work, so it is not a gap.
//!
//! A non-empty outbox is deliberately **not** part of the gate. The head of
//! the outbox may belong to an operation the server has not sequenced yet (a
//! writer mid-stream), and every frame that does carry a watermark is already
//! counted by `work_seq`.
//!
//! # Clock
//!
//! The clock measures from `max(last_advance_at, last_work_at)`. The first
//! term is the last client report; the second is the instant the oldest still
//! outstanding operation was sequenced. Measuring from the tick alone would
//! give an operation that appears just before a tick almost no budget, while
//! measuring from every new operation would let a stuck client hide behind
//! its peers' writes.
//!
//! # Reporting
//!
//! A diagnosis is throttled per client: one log line per
//! [`HealthLimits::diagnosis_interval`]. The metrics gauges read every
//! diagnosis, throttled or not.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::protocol::{Seq, SessionId};

use super::online::{Session, WatermarkVerdict};

/// Fallback P99 when no RTT sample exists (42 D8).
pub const DEFAULT_RTT_P99_MS: u16 = 300;

/// Conservative throughput used to price backlog (42 §6.1).
pub const MIN_THROUGHPUT_BPS: u64 = 1024 * 1024;

/// Conservative local apply cost per pending operation.
pub const MAX_OP_APPLY: Duration = Duration::from_millis(100);

/// Threshold ceiling; keeps `pending_ops × 100 ms` from overflowing.
pub const MAX_THRESHOLD: Duration = Duration::from_secs(24 * 60 * 60);

/// Minimum spacing between two log lines for the same client.
pub const DIAGNOSIS_INTERVAL: Duration = Duration::from_secs(30);

/// Frozen health constants; tests may shrink timeouts without changing the
/// formula.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HealthLimits {
    /// Multiplier on `RTT_p99`.
    pub k_rtt: u32,
    /// Conservative throughput in bytes per second.
    pub min_throughput_bps: u64,
    /// Conservative apply cost per pending op.
    pub max_op_apply: Duration,
    /// Threshold ceiling.
    pub max_threshold: Duration,
    /// Minimum spacing between two log lines for one client.
    pub diagnosis_interval: Duration,
}

impl Default for HealthLimits {
    fn default() -> Self {
        Self {
            k_rtt: 3,
            min_throughput_bps: MIN_THROUGHPUT_BPS,
            max_op_apply: MAX_OP_APPLY,
            max_threshold: MAX_THRESHOLD,
            diagnosis_interval: DIAGNOSIS_INTERVAL,
        }
    }
}

/// One observation that a session is behind its threshold.
///
/// Diagnostic only: the caller logs it and publishes the gauges. Nothing in
/// this module turns a diagnosis into a kick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Diagnosis {
    /// `work_seq - applied_seq`.
    pub pending_ops: u64,
    /// Outbox bytes not yet handed to the socket.
    pub backlog_bytes: u64,
    /// Time since the oldest outstanding operation (or the last report).
    pub lag: Duration,
    /// Threshold the lag exceeded.
    pub threshold: Duration,
}

/// Per-session health state that is not part of the online table.
#[derive(Debug)]
pub struct HealthMonitor {
    limits: HealthLimits,
    /// Last log instant per client, to keep warning volume bounded.
    reported: HashMap<SessionId, Instant>,
}

impl HealthMonitor {
    /// Build a monitor with explicit constants.
    pub fn new(limits: HealthLimits) -> Self {
        Self {
            limits,
            reported: HashMap::new(),
        }
    }

    /// Borrow the constants.
    pub const fn limits(&self) -> &HealthLimits {
        &self.limits
    }

    /// Dynamic threshold for one session.
    ///
    /// `work_seq` is the highest `ORDERED` sequence the server has
    /// sequenced, never the raw counter: a `LEAVE` consumes a sequence but
    /// assigns no work.
    pub fn threshold(&self, session: &Session, work_seq: Seq) -> Duration {
        let rtt_ms = u64::from(session.watermark.rtt().p99().unwrap_or(DEFAULT_RTT_P99_MS));
        let backlog = session.outbox.queued.bytes();
        let pending = work_seq
            .get()
            .saturating_sub(session.watermark.applied_seq().get());

        let rtt_ns = u128::from(rtt_ms)
            .saturating_mul(u128::from(self.limits.k_rtt))
            .saturating_mul(1_000_000);
        let throughput = self.limits.min_throughput_bps.max(1);
        let backlog_ns = u128::from(backlog).saturating_mul(1_000_000_000) / u128::from(throughput);
        let ops_ns = u128::from(pending).saturating_mul(self.limits.max_op_apply.as_nanos());
        let total = rtt_ns
            .saturating_add(backlog_ns)
            .saturating_add(ops_ns)
            .min(self.limits.max_threshold.as_nanos());
        Duration::from_nanos(u64::try_from(total).unwrap_or(u64::MAX))
    }

    /// Apply one watermark observation.
    ///
    /// T2/T3 are decided by [`super::online::Watermark::observe`]. An epoch
    /// mismatch is reported to the sequencer, which kicks the session so it
    /// reconnects and replays under the current epoch.
    pub fn on_watermark(
        &mut self,
        session: &mut Session,
        applied: Seq,
        epoch_seen: u64,
        epoch: u64,
        current: Seq,
        at: std::time::Instant,
    ) -> WatermarkVerdict {
        session
            .watermark
            .observe(applied, epoch_seen, epoch, current, at)
    }

    /// Report how far one session is behind, if at all.
    ///
    /// Returns `None` when the session is caught up; the idle reset happens
    /// here, which is the only place that needs `&mut Session`. A `Some`
    /// value is a diagnosis, not a death sentence: the caller logs it and
    /// updates the gauges, and the session stays attached.
    ///
    /// `work_seq` is the highest `ORDERED` sequence; see [`Self::threshold`].
    pub fn diagnose(
        &mut self,
        session: &mut Session,
        work_seq: Seq,
        now: std::time::Instant,
    ) -> Option<Diagnosis> {
        // Only an unapplied `ORDERED` is work. Queued bytes alone are not: the
        // head of the outbox may belong to an operation the server has not
        // sequenced yet, and every frame that carries a watermark is already
        // counted by `work_seq`.
        let busy = work_seq > session.watermark.applied_seq();
        if !busy {
            session.watermark.note_idle(now);
            self.reported.remove(&session.session_id);
            return None;
        }
        let threshold = self.threshold(session, work_seq);
        // The clock starts when the oldest outstanding operation appeared.
        // Measuring from the last tick alone would give an operation
        // sequenced just before a tick almost no budget at all.
        let since_work = session
            .watermark
            .last_advance_at()
            .max(session.watermark.last_work_at());
        let lag = now.saturating_duration_since(since_work);
        if lag <= threshold {
            self.reported.remove(&session.session_id);
            return None;
        }
        Some(Diagnosis {
            pending_ops: work_seq
                .get()
                .saturating_sub(session.watermark.applied_seq().get()),
            backlog_bytes: session.outbox.queued.bytes(),
            lag,
            threshold,
        })
    }

    /// Whether a diagnosis for `client` should produce a log line now.
    ///
    /// At most one line per [`HealthLimits::diagnosis_interval`]. Metrics do
    /// not go through this gate.
    pub fn should_report(&mut self, client: SessionId, now: Instant) -> bool {
        match self.reported.get(&client) {
            Some(last) if now.saturating_duration_since(*last) < self.limits.diagnosis_interval => {
                false
            }
            _ => {
                self.reported.insert(client, now);
                true
            }
        }
    }

    /// Drop the per-client report bookkeeping when a session detaches.
    pub fn forget(&mut self, client: SessionId) {
        self.reported.remove(&client);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::protocol::KickReason;
    use crate::server::config::OutboxConfig;
    use crate::server::online::{Outbox, SessionInit, SessionState};
    use crate::transport::PeerId;
    use std::time::Instant;

    fn client(byte: u8) -> SessionId {
        SessionId(u128::from_le_bytes([byte; 16]))
    }

    fn session(at: Instant) -> Session {
        let (outbox, _data, _ctrl) = Outbox::new(&OutboxConfig::default());
        Session::new(SessionInit {
            session_id: client(1),
            nonce: 1,
            peer: PeerId::from_serial(1),
            outbox,
            epoch: 7,
            epoch_seen: 7,
            applied_seq: Seq::UNSEQUENCED,
            current_seq: Seq::UNSEQUENCED,
            now: at,
        })
    }

    #[test]
    fn server_health_threshold_matches_the_frozen_formula() {
        let at = Instant::now();
        let mut session = session(at);
        for _ in 0..60 {
            session.watermark.push_rtt(100);
        }
        session.outbox.queued.add(1024 * 1024);
        let monitor = HealthMonitor::new(HealthLimits::default());
        assert_eq!(
            monitor.threshold(&session, Seq(10)),
            Duration::from_millis(300 + 1000 + 1000),
            "3*100ms + 1MiB/1MiBps + 10*100ms"
        );
    }

    #[test]
    fn server_health_threshold_falls_back_to_300ms_and_caps_at_24h() {
        let at = Instant::now();
        let session = session(at);
        let monitor = HealthMonitor::new(HealthLimits::default());
        assert_eq!(
            monitor.threshold(&session, Seq(10)),
            Duration::from_millis(900 + 1000)
        );
        assert_eq!(monitor.threshold(&session, Seq(u64::MAX)), MAX_THRESHOLD);
    }

    #[test]
    fn server_health_diagnose_fires_one_nanosecond_past_the_threshold() {
        let at = Instant::now();
        let mut session = session(at);
        for _ in 0..60 {
            session.watermark.push_rtt(100);
        }
        session.outbox.queued.add(1024 * 1024);
        let mut monitor = HealthMonitor::new(HealthLimits::default());
        let threshold = monitor.threshold(&session, Seq(10));
        assert_eq!(
            monitor.diagnose(&mut session, Seq(10), at + threshold),
            None
        );
        let diagnosis = monitor
            .diagnose(
                &mut session,
                Seq(10),
                at + threshold + Duration::from_nanos(1),
            )
            .expect("lag past the threshold is a diagnosis");
        assert_eq!(diagnosis.pending_ops, 10);
        assert_eq!(diagnosis.backlog_bytes, 1024 * 1024);
        assert_eq!(diagnosis.threshold, threshold);
    }

    #[test]
    fn server_health_idle_gate_resets_the_clock_instead_of_reporting() {
        let at = Instant::now();
        let mut session = session(at);
        let mut monitor = HealthMonitor::new(HealthLimits::default());
        let later = at + Duration::from_secs(3600);
        session.last_seen_at = later;
        assert_eq!(monitor.diagnose(&mut session, Seq(0), later), None);
        assert_eq!(session.watermark.last_advance_at(), later);
        // With work again, the clock starts from the reset instant.
        assert_eq!(
            monitor.diagnose(&mut session, Seq(10), later + Duration::from_secs(1)),
            None
        );
    }

    /// An operation that appears just before a tick still gets its whole
    /// threshold: the clock starts when the work appeared, not at the tick.
    #[test]
    fn server_health_work_clock_starts_at_the_operation() {
        let at = Instant::now();
        let mut session = session(at);
        let mut monitor = HealthMonitor::new(HealthLimits::default());
        // The idle tick resets the advance clock to `at`.
        assert_eq!(monitor.diagnose(&mut session, Seq(0), at), None);
        assert_eq!(session.watermark.last_advance_at(), at);

        // One operation appears 900 ms later; the tick is 5 ms late. The old
        // clock (1005 ms) would already exceed the 1 s threshold.
        let work = at + Duration::from_millis(900);
        session.watermark.note_work(work);
        let tick = at + Duration::from_millis(1005);
        session.last_seen_at = tick;
        assert_eq!(
            monitor.diagnose(&mut session, Seq(1), tick),
            None,
            "the operation must get its full threshold from its own instant"
        );
        assert!(
            monitor
                .diagnose(
                    &mut session,
                    Seq(1),
                    work + Duration::from_millis(1_000) + Duration::from_nanos(1)
                )
                .is_some()
        );
    }

    /// Work that arrives behind an already-outstanding operation must not
    /// extend the clock, or a stuck client could hide behind its peers'
    /// writes.
    #[test]
    fn server_health_outstanding_work_keeps_the_clock() {
        let at = Instant::now();
        let mut session = session(at);
        let mut monitor = HealthMonitor::new(HealthLimits::default());
        session.watermark.note_work(at);
        // Three operations are outstanding; `note_work` is not called again
        // because the session was never caught up.
        let later = at + Duration::from_secs(5);
        session.last_seen_at = later;
        assert!(monitor.diagnose(&mut session, Seq(3), later).is_some());
    }

    /// W20 repro: `applied_seq` equals the last `ORDERED`, the outbox still
    /// holds the tail of a stream, and repeated `PING`s report no change.
    /// That is an idle session, not a lagging one.
    #[test]
    fn server_health_residual_backlog_without_pending_ops_is_idle() {
        let at = Instant::now();
        let mut session = session(at);
        let mut monitor = HealthMonitor::new(HealthLimits::default());
        assert_eq!(
            monitor.on_watermark(&mut session, Seq(7), 7, 7, Seq(7), at),
            WatermarkVerdict::Advanced
        );
        session.outbox.queued.add(300);

        // Five seconds later the client still reports 7. The outbox tail
        // must not turn that into lag.
        let later = at + Duration::from_secs(5);
        session.last_seen_at = later;
        assert_eq!(
            monitor.diagnose(&mut session, Seq(7), later),
            None,
            "applied_seq == last ORDERED must be idle whatever the outbox holds"
        );
        assert_eq!(session.watermark.last_advance_at(), later);

        // One unapplied operation still counts, with the backlog priced in.
        assert_eq!(
            monitor.diagnose(&mut session, Seq(8), later),
            None,
            "no time has passed since the idle reset"
        );
        assert!(
            monitor
                .diagnose(&mut session, Seq(8), later + Duration::from_millis(2_000))
                .is_some()
        );
    }

    /// A diagnosis produces at most one log line per interval.
    #[test]
    fn server_health_diagnosis_is_logged_at_most_once_per_interval() {
        let at = Instant::now();
        let mut session = session(at);
        let mut monitor = HealthMonitor::new(HealthLimits::default());
        // One pending op keeps the threshold at ~1 s, so 60 s of silence is
        // unambiguously past it.
        let work = Seq(1);
        session.watermark.note_work(at);
        let lagging = at + Duration::from_secs(60);
        assert!(monitor.diagnose(&mut session, work, lagging).is_some());
        assert!(monitor.should_report(session.session_id, lagging));
        assert!(!monitor.should_report(session.session_id, lagging + Duration::from_secs(1)));
        assert!(monitor.should_report(session.session_id, lagging + DIAGNOSIS_INTERVAL));
        // Caught up: the entry is dropped, so the next episode logs at once.
        assert_eq!(monitor.diagnose(&mut session, Seq(0), lagging), None);
        assert!(monitor.should_report(session.session_id, lagging));
    }

    #[test]
    fn server_health_watermark_t2_t3_and_epoch_resync() {
        let at = Instant::now();
        let mut session = session(at);
        let mut monitor = HealthMonitor::new(HealthLimits::default());
        assert_eq!(
            monitor.on_watermark(&mut session, Seq(5), 7, 7, Seq(10), at),
            WatermarkVerdict::Advanced
        );
        assert_eq!(
            monitor.on_watermark(&mut session, Seq(4), 7, 7, Seq(10), at),
            WatermarkVerdict::Kick(KickReason::Regression)
        );
        assert_eq!(
            monitor.on_watermark(&mut session, Seq(11), 7, 7, Seq(10), at),
            WatermarkVerdict::Kick(KickReason::Overclaim)
        );
        assert_eq!(
            monitor.on_watermark(&mut session, Seq(6), 6, 7, Seq(10), at),
            WatermarkVerdict::EpochMismatch
        );
        assert_eq!(
            session.state,
            SessionState::Replaying,
            "health must not mutate the lifecycle; the sequencer kicks on mismatch"
        );
    }

    #[test]
    fn server_health_threshold_prices_backlog_without_losing_sub_mib_precision() {
        let at = Instant::now();
        let session = session(at);
        session.outbox.queued.add(512 * 1024);
        let monitor = HealthMonitor::new(HealthLimits::default());
        assert_eq!(
            monitor.threshold(&session, Seq(0)),
            Duration::from_millis(900 + 500)
        );
    }
}
