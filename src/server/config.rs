//! Server configuration and frozen constants.
//!
//! Every tunable lives here, so a deployment changes numbers in one place and
//! never inside the actor or the HTTP layer (42 §2.1). The defaults are the
//! values frozen by 39/42/51; [`ServeConfig::for_tests`] changes sizes and
//! timeouts, never a semantic ratio.

use std::net::SocketAddr;
use std::time::Duration;

use crate::protocol::Limits;
use crate::transport::PAIR_TIMEOUT;

/// Bounded command queue in front of the sequencer (42 §3.4 L1).
pub const COMMAND_CAPACITY: usize = 1024;

/// Hard outbound budget per session, in bytes (42 §3.3 L2).
///
/// Raised from 8 MiB: a joiner pulling a large view legitimately buffers
/// several megabytes, and the cap is a memory bound, not a speed test.
pub const OUTBOX_CAP_BYTES: u64 = 32 * 1024 * 1024;

/// Hard outbound budget per session, in frames.
pub const OUTBOX_CAP_FRAMES: u32 = 512;

/// Data frames buffered between the actor and one session's writer.
pub const OUTBOX_DATA_FRAMES: usize = 512;

/// Control frames buffered ahead of data (WELCOME/KICK/ERROR).
pub const OUTBOX_CTRL_FRAMES: usize = 32;

/// Default tick period (42 §6.2).
pub const TICK_INTERVAL: Duration = Duration::from_secs(1);

/// Maximum wait for the downlink half of a session (42 §7.3).
pub const HELLO_TIMEOUT: Duration = PAIR_TIMEOUT;

/// Clients above which `healthz` reports `degraded` (42 §7.4).
pub const DEGRADED_CLIENTS: u64 = 8000;

/// Per-session outbound queue budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutboxConfig {
    /// Hard byte ceiling across queued data frames.
    pub cap_bytes: u64,
    /// Hard frame ceiling across queued data frames.
    pub cap_frames: u32,
    /// Channel capacity for data frames.
    pub data_frames: usize,
    /// Channel capacity for control frames.
    pub ctrl_frames: usize,
}

impl Default for OutboxConfig {
    fn default() -> Self {
        Self {
            cap_bytes: OUTBOX_CAP_BYTES,
            cap_frames: OUTBOX_CAP_FRAMES,
            data_frames: OUTBOX_DATA_FRAMES,
            ctrl_frames: OUTBOX_CTRL_FRAMES,
        }
    }
}

/// Values advertised in `WELCOME.limits`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WelcomeConfig {
    /// Flow-control credit window.
    pub credit_bytes: u32,
    /// Sync-session time-to-live, in seconds.
    pub session_ttl_s: u32,
    /// Maximum concurrent relay sessions.
    pub max_sessions: u32,
}

impl Default for WelcomeConfig {
    fn default() -> Self {
        Self {
            credit_bytes: 8 * 1024 * 1024,
            session_ttl_s: 30 * 60,
            max_sessions: 32,
        }
    }
}

/// Everything one `syncmount serve` process needs to start.
#[derive(Clone, Debug)]
pub struct ServeConfig {
    /// TCP address to bind.
    pub listen: SocketAddr,
    /// URL path prefix; normalized by the HTTP acceptor.
    pub namespace: String,
    /// Frame-parsing limits (ingress cap, WCP cap, path cap, detail cap).
    pub limits: Limits,
    /// Outbound queue budget.
    pub outbox: OutboxConfig,
    /// Values advertised to clients.
    pub welcome: WelcomeConfig,
    /// Command queue depth.
    pub command_capacity: usize,
    /// Period of the sequencer tick.
    pub tick_interval: Duration,
    /// How long a downlink may wait for its uplink.
    pub pair_timeout: Duration,
    /// How long an uplink may wait for its downlink.
    pub hello_timeout: Duration,
}

impl ServeConfig {
    /// Production defaults for one listen address and the root namespace.
    pub fn new(listen: SocketAddr) -> Self {
        Self {
            listen,
            namespace: "/".to_owned(),
            limits: Limits::default(),
            outbox: OutboxConfig::default(),
            welcome: WelcomeConfig::default(),
            command_capacity: COMMAND_CAPACITY,
            tick_interval: TICK_INTERVAL,
            pair_timeout: PAIR_TIMEOUT,
            hello_timeout: HELLO_TIMEOUT,
        }
    }

    /// Loopback defaults, useful for a one-line test setup.
    pub fn loopback() -> Self {
        Self::new(SocketAddr::from(([127, 0, 0, 1], 0)))
    }

    /// Small timeouts and large queues: fast tests, same semantics.
    ///
    /// The queue ceiling is raised because the invariant tests push ten
    /// thousand frames through sessions that never block; the byte budget
    /// still applies.
    pub fn for_tests() -> Self {
        Self {
            outbox: OutboxConfig {
                cap_bytes: 64 * 1024 * 1024,
                cap_frames: 20_000,
                data_frames: 20_000,
                ctrl_frames: 64,
            },
            command_capacity: 4096,
            tick_interval: Duration::from_millis(10),
            pair_timeout: Duration::from_millis(50),
            hello_timeout: Duration::from_millis(200),
            ..Self::loopback()
        }
    }
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self::loopback()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_config_defaults_are_the_frozen_numbers() {
        let config = ServeConfig::default();
        assert_eq!(config.outbox.cap_bytes, 32 * 1024 * 1024);
        assert_eq!(config.outbox.cap_frames, 512);
        assert_eq!(config.command_capacity, 1024);
        assert_eq!(config.pair_timeout, Duration::from_secs(10));
        assert_eq!(config.welcome.max_sessions, 32);
    }

    #[test]
    fn server_config_test_profile_is_smaller_and_larger() {
        let tests = ServeConfig::for_tests();
        let production = ServeConfig::default();
        assert!(tests.pair_timeout < production.pair_timeout);
        assert!(tests.tick_interval < production.tick_interval);
        assert!(tests.outbox.cap_frames > production.outbox.cap_frames);
        assert_eq!(tests.outbox.cap_bytes, 64 * 1024 * 1024);
    }
}
