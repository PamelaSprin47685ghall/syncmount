//! Atomic mirrors read by `healthz`.
//!
//! Every field is a relaxed atomic: a probe never sends a command to the
//! actor and never waits behind a saturated sequencer (42 §7.4, 42 V10).
//! The actor is the only writer; readers are the HTTP probe and tests.
//!
//! The JSON shape is frozen by 42 §7.4. Adding a field changes the probe
//! contract, so relay and health counters stay in their own modules rather
//! than leaking into this object.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use super::Epoch;
use super::config::DEGRADED_CLIENTS;

/// Atomic mirrors read by `healthz`.
#[derive(Debug)]
pub struct Metrics {
    /// Server epoch.
    pub epoch: Epoch,
    /// Process start instant.
    pub started_at: Instant,
    /// Current sequence.
    pub seq: AtomicU64,
    /// Attached sessions.
    pub clients: AtomicU64,
    /// Relay sessions; the relay hub writes this through the actor.
    pub sync_sessions: AtomicU64,
    /// Highest watermark lag across sessions, in milliseconds.
    pub watermark_lag_ms: AtomicU64,
    /// Highest pending-op count across sessions.
    pub pending_ops: AtomicU64,
    /// Data frames dropped because a draining queue hit its budget.
    pub dropped_frames: AtomicU64,
}

impl Metrics {
    /// Fresh counters for one process start.
    pub fn new(epoch: Epoch) -> Self {
        Self {
            epoch,
            started_at: Instant::now(),
            seq: AtomicU64::new(0),
            clients: AtomicU64::new(0),
            sync_sessions: AtomicU64::new(0),
            watermark_lag_ms: AtomicU64::new(0),
            pending_ops: AtomicU64::new(0),
            dropped_frames: AtomicU64::new(0),
        }
    }

    /// Publish the actor-owned sequence.
    pub fn publish_seq(&self, seq: u64) {
        self.seq.store(seq, Ordering::Release);
    }

    /// Publish the attached-session count.
    pub fn publish_clients(&self, clients: usize) {
        self.clients.store(clients as u64, Ordering::Release);
    }

    /// Publish the relay-session count.
    pub fn publish_sync_sessions(&self, sessions: usize) {
        self.sync_sessions.store(sessions as u64, Ordering::Release);
    }

    /// Fixed `healthz` JSON (42 §7.4).
    ///
    /// `status` is the only field a probe must interpret. `degraded` means
    /// the attached-session count crossed the frozen threshold; queue
    /// pressure is reported through kicks, not through this probe.
    pub fn healthz(&self) -> String {
        let clients = self.clients.load(Ordering::Relaxed);
        let status = if clients > DEGRADED_CLIENTS {
            "degraded"
        } else {
            "ok"
        };
        format!(
            concat!(
                "{{\"status\":\"{}\",\"version\":\"{}\",\"mode\":\"serve\",",
                "\"clients\":{},\"uptime_s\":{},\"seq\":{},\"epoch\":\"0x{:016x}\",",
                "\"sync_sessions\":{}}}"
            ),
            status,
            env!("CARGO_PKG_VERSION"),
            clients,
            self.started_at.elapsed().as_secs(),
            self.seq.load(Ordering::Relaxed),
            self.epoch.get(),
            self.sync_sessions.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_metrics_healthz_has_the_frozen_fields_and_live_counters() {
        let metrics = Metrics::new(Epoch::new(0x2a));
        metrics.publish_seq(7);
        metrics.publish_clients(2);
        metrics.publish_sync_sessions(3);
        let json = metrics.healthz();
        assert!(json.starts_with("{\"status\":\"ok\""));
        assert!(json.contains("\"clients\":2"));
        assert!(json.contains("\"seq\":7"));
        assert!(json.contains("\"epoch\":\"0x000000000000002a\""));
        assert!(json.contains("\"sync_sessions\":3"));
        assert!(!json.contains("broadcast_log_entries"));
    }

    #[test]
    fn server_metrics_healthz_degrades_only_past_the_frozen_threshold() {
        let metrics = Metrics::new(Epoch::new(1));
        metrics.publish_clients(DEGRADED_CLIENTS as usize);
        assert!(metrics.healthz().contains("\"status\":\"ok\""));
        metrics.publish_clients(DEGRADED_CLIENTS as usize + 1);
        assert!(metrics.healthz().contains("\"status\":\"degraded\""));
    }
}
