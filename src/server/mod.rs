//! Server: HTTP surface, one sequencer actor, SQLite authority.
//!
//! # Scope
//!
//! ```text
//! http      HttpAcceptor -> POST {prefix}/rpc, GET {prefix}/events, healthz
//! session   PSK handshake, per-connection reader/writer, OP_DATA assembly
//! sequencer single actor: commit, fanout, replay cursor, LEAVE, drain
//! store     one blocking thread: SQLite transaction, state mirror, wire log
//! wire      ORDERED <-> state::Op / EventDraft / replay frames
//! online    OnlineTable keyed by SessionId, Outbox, Watermark
//! config    ServeConfig and every frozen constant
//! ```
//!
//! # Ordering and durability
//!
//! The server holds the PSK. It decrypts `ORDERED`, decodes the operation,
//! plans it with the shared `state` machine, commits the row changes and the
//! event in one SQLite transaction, and only then broadcasts the client's
//! original ciphertext with `header.seq` rewritten. A crash between commit
//! and broadcast is repaired by replay; the reverse order is forbidden.
//!
//! # Identity
//!
//! A session is the server-assigned [`protocol::SessionId`]. The wire still
//! carries `client_id`, but the server never uses it for routing or trust:
//! the PSK is the only credential. An unauthenticated connection never enters
//! the online table.
pub mod config;
pub mod health;
pub mod http;
pub mod kick;
pub mod metrics;
pub mod online;
pub mod relay;
pub mod sequencer;
pub mod store;
pub mod wire;

mod session;

use std::fmt;

pub use config::{OutboxConfig, ServeConfig, WelcomeConfig};
pub use health::{HealthLimits, HealthMonitor};
pub use http::{Server, ServerError};
pub use kick::{KickPlan, injects_leave};
pub use metrics::Metrics;
pub use online::{
    DRAIN_GRACE, OnlineTable, Outbox, PushOutcome, QueueStats, RttRing, Session, SessionInit,
    SessionState, Watermark, WatermarkVerdict,
};
pub use relay::{RelayHub, RelayLimits, RelaySession, RelayState, RouteAction, Window};
pub use sequencer::{
    AttachReply, AttachRequest, DetachCause, DrainReport, EventsOutcome, EventsReject, PairReply,
    ReplayStep, SeqCmd, SeqSnapshot, Sequencer, SequencerError, WatermarkReport,
};
pub use store::{CommitOutcome, CommitRequest, StoreHandle, StoreMeta};

/// Event-log epoch.
///
/// Persisted in `meta.epoch`. A normal restart keeps it, so clients resume
/// from their applied sequence; only compaction increments it and resets the
/// sequence to zero. Clients compare this value; it never orders events.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Epoch(u64);

impl Epoch {
    /// Wrap a known value. Tests use this to make restarts deterministic.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Draw a fresh epoch from process entropy.
    pub fn generate() -> Self {
        Self(rand::random::<u64>())
    }

    /// Raw value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for Epoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Epoch(0x{:016x})", self.0)
    }
}

impl fmt::Display for Epoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "0x{:016x}", self.0)
    }
}

#[cfg(test)]
mod integration_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_epoch_is_diagnostic_and_hex_rendered() {
        let epoch = Epoch::new(0x9f3c);
        assert_eq!(epoch.get(), 0x9f3c);
        assert_eq!(epoch.to_string(), "0x0000000000009f3c");
    }

    #[test]
    fn server_epoch_generation_changes_per_process() {
        let first = Epoch::generate();
        let second = Epoch::generate();
        assert_ne!(first, second, "64 random bits; collision is negligible");
    }
}
