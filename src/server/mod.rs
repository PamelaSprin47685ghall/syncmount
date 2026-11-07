//! Server: HTTP surface, one sequencer actor, online table.
//!
//! # Scope
//!
//! W9 owns the total order and the session lifecycle:
//!
//! ```text
//! http      HttpAcceptor → POST {prefix}/rpc, GET {prefix}/events, healthz
//! session   per-connection reader/writer, nonce pairing, detach
//! sequencer single actor: stamp, fan-out, watermark T2/T3, LEAVE, tick
//! online    OnlineTable, SessionState, Outbox (32 MiB ceiling), Watermark
//! config    ServeConfig and every frozen constant
//! ```
//!
//! W10 adds `relay`, `health`, `kick`, `snapshot_registry` and `metrics`. The
//! seams are deliberate: [`session`] hands every routed frame to
//! [`SeqCmd::Relay`], and [`Metrics::sync_sessions`] is written by the relay
//! hub through the actor.
//!
//! # What the server never does
//!
//! It holds no key, parses no `enc_body`, writes no disk, keeps no replay
//! window and never rewrites a routed prefix (42 §0, I4–I8). The only header
//! field it touches is `seq`.

pub mod config;
pub mod health;
pub mod http;
pub mod kick;
pub mod metrics;
pub mod online;
pub mod relay;
pub mod sequencer;
pub mod snapshot_registry;
pub mod view_registry;

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
    DetachCause, EventsOutcome, EventsReject, HelloReply, HelloRequest, SeqCmd, SeqSnapshot,
    Sequencer, SequencerError, WatermarkReport,
};
pub use snapshot_registry::{SnapshotAction, SnapshotEntry, SnapshotLimits, SnapshotRegistry};
pub use view_registry::{ViewChoice, ViewLookup, ViewRegistry, ViewRoute, ViewSource};

/// Random per-process epoch.
///
/// Never persisted (39 ruling 10): a restart produces a new epoch, the
/// sequence restarts at zero, and every client resynchronizes. Clients compare
/// this value; it never orders events.
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
