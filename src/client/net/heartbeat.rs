//! Client heartbeat: when to send `PING` and what its ctrl prefix carries.
//!
//! A `PING` reports the watermark the replay pump has applied. Liveness is
//! the connection's job — the server watches the socket, not this frame — so
//! the scheduler has exactly one rule:
//!
//! * report every watermark change, coalesced to one `PING` per
//!   [`MIN_REPORT_INTERVAL`], so a sequenced op is acknowledged within one
//!   server tick.
//!
//! An idle session sends nothing. There is no periodic keepalive: a mount
//! that applies no frames puts no bytes on the uplink at all.
//!
//! The first report of a session is the change from "nothing reported by this
//! scheduler" to the current watermark. `HELLO` carried the watermark at
//! attach time; frames the replay pump applies between `HELLO` and the first
//! uplink iteration would otherwise stay unreported, so one report closes
//! that gap and every later report is a genuine advance.
//!
//! The frame itself is built by [`ping_frame`] and written by
//! [`super::uplink::UplinkTask`], the only writer of the RPC stream; this
//! module owns no socket and no task.
//!
//! # Watermark
//!
//! The 18-byte `ctrl_prefix` is the whole report (44 §2.1):
//!
//! ```text
//! applied_seq u64 | epoch_seen u64 | reserved u16 (= 0)
//! ```
//!
//! `reserved` stays zero: 32 §2.1 freezes it, and the server rejects a
//! non-zero value. RTT is therefore not reported (see
//! `docs/known-limitations.md` §1.10); the server keeps its 300 ms fallback,
//! which the per-op terms of the lag formula still adapt.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::protocol::crypto::{KeyRing, NonceMinter, Sealer};
use crate::protocol::messages::Ping;
use crate::protocol::{CtrlPrefix, Flags, FrameBuf, FrameHeader, MsgType, Prefix, Seq};

use super::conn::UplinkError;

/// Coalescing floor for change-driven reports.
///
/// A report that lags a sequenced op by at most this long is cheap, and a
/// burst of applied frames collapses into one `PING`.
pub const MIN_REPORT_INTERVAL: Duration = Duration::from_millis(10);

/// The watermark one `PING` reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Watermark {
    /// Highest sequence the replay pump has applied.
    pub applied: Seq,
    /// Server epoch the client last saw.
    pub epoch_seen: u64,
}

/// Live view of the replay pump's watermark.
///
/// The two counters are the same atomics the status document publishes, so a
/// `PING` never needs to borrow the replayer and never blocks the replay
/// pump. Cloning the reader clones the handles, not the values.
#[derive(Clone, Debug)]
pub struct WatermarkReader {
    applied: Arc<AtomicU64>,
    epoch: Arc<AtomicU64>,
}

impl WatermarkReader {
    /// Read the two counters behind `applied` and `epoch`.
    pub fn new(applied: Arc<AtomicU64>, epoch: Arc<AtomicU64>) -> Self {
        Self { applied, epoch }
    }

    /// Current watermark.
    pub fn read(&self) -> Watermark {
        Watermark {
            applied: Seq(self.applied.load(Ordering::Relaxed)),
            epoch_seen: self.epoch.load(Ordering::Relaxed),
        }
    }
}

/// `PING` scheduler.
///
/// `due` is the only entry point: it answers "send now?" and records the
/// send, so the caller cannot forget to advance the clock.
#[derive(Debug)]
pub struct Heartbeat {
    min_report: Duration,
    last_sent: Option<Watermark>,
    last_sent_at: Option<Instant>,
}

impl Heartbeat {
    /// Scheduler with the frozen coalescing floor.
    pub fn new() -> Self {
        Self::with_min_report(MIN_REPORT_INTERVAL)
    }

    /// Scheduler with an explicit coalescing floor; tests shrink it.
    pub fn with_min_report(min_report: Duration) -> Self {
        Self {
            min_report,
            last_sent: None,
            last_sent_at: None,
        }
    }

    /// Return the watermark to report when a `PING` is due.
    ///
    /// A changed watermark is reported at once, then at most once per
    /// `min_report`. An unchanged one is never reported, so an idle session
    /// sends no frames. The first call always sends: it is the change from
    /// "not yet reported" to the current watermark, and it tells the server
    /// what the replay pump applied after `HELLO`.
    pub fn due(&mut self, now: Instant, watermark: Watermark) -> Option<Watermark> {
        let changed = self.last_sent != Some(watermark);
        let elapsed = self
            .last_sent_at
            .map(|at| now.saturating_duration_since(at));
        let ready = elapsed.is_none_or(|elapsed| elapsed >= self.min_report);
        if !(changed && ready) {
            return None;
        }
        self.last_sent = Some(watermark);
        self.last_sent_at = Some(now);
        Some(watermark)
    }
}

impl Default for Heartbeat {
    fn default() -> Self {
        Self::new()
    }
}

/// Build one sealed `PING` frame.
///
/// The body is a sealed WCP `Ping` (44 §3.4); the prefix is the plaintext
/// watermark the server reads without any key. `client_time_us` is opaque to
/// the server and only lets a capture line the frame up with the local log.
pub fn ping_frame(
    watermark: Watermark,
    client_time_us: u64,
    ring: &KeyRing,
    nonces: &NonceMinter,
) -> Result<FrameBuf, UplinkError> {
    let body = (Ping {
        client_time: client_time_us,
    })
    .encode()?;
    let prefix = Prefix::Ctrl(CtrlPrefix::new(watermark.applied, watermark.epoch_seen));
    let mut header = FrameHeader::new(
        MsgType::PING,
        Flags::ENC.with(Flags::CTRL),
        0,
        Seq::UNSEQUENCED,
    );
    let sealed = Sealer::new(ring, nonces).seal(&mut header, &prefix, &body)?;
    Ok(FrameBuf::new(header, prefix, sealed.into_vec()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::protocol::crypto::{ClusterId, Opener};
    use crate::protocol::{FrameDecoder, Limits};

    fn at(ms: u64) -> Instant {
        Instant::now() + Duration::from_millis(ms)
    }

    fn watermark(applied: u64, epoch_seen: u64) -> Watermark {
        Watermark {
            applied: Seq(applied),
            epoch_seen,
        }
    }

    /// The first call primes the server, a change is reported immediately,
    /// and a burst of changes is coalesced to one report per interval.
    #[test]
    fn u_heartbeat_reports_first_change_and_coalesces_bursts() {
        let mut heartbeat = Heartbeat::new();
        let start = at(0);
        assert_eq!(heartbeat.due(start, watermark(0, 1)), Some(watermark(0, 1)));
        assert_eq!(heartbeat.due(start, watermark(0, 1)), None, "unchanged");

        // A change right after a send waits for the coalescing floor.
        assert_eq!(heartbeat.due(start, watermark(1, 1)), None);
        assert_eq!(
            heartbeat.due(start + MIN_REPORT_INTERVAL, watermark(1, 1)),
            Some(watermark(1, 1))
        );

        // Eleven changes inside one interval produce exactly one report, and
        // that report carries the newest watermark.
        let burst = start + MIN_REPORT_INTERVAL;
        let mut sent = Vec::new();
        for step in 0..=10u64 {
            if let Some(reported) =
                heartbeat.due(burst + Duration::from_millis(step), watermark(2 + step, 1))
            {
                sent.push(reported);
            }
        }
        assert_eq!(sent, vec![watermark(12, 1)], "burst must coalesce");
        assert_eq!(
            heartbeat.due(burst + Duration::from_millis(20), watermark(13, 1)),
            Some(watermark(13, 1))
        );
    }

    /// An idle session sends nothing: ten minutes of an unchanged watermark
    /// produce no frame, and the next real change is still reported at once.
    #[test]
    fn u_heartbeat_idle_session_sends_nothing_for_600s() {
        let mut heartbeat = Heartbeat::new();
        let start = at(0);
        // The session-start report closes the HELLO-to-uplink gap; after it
        // the scheduler is silent.
        assert_eq!(heartbeat.due(start, watermark(4, 2)), Some(watermark(4, 2)));
        for second in 1..=600u64 {
            assert_eq!(
                heartbeat.due(start + Duration::from_secs(second), watermark(4, 2)),
                None,
                "idle second {second} must send nothing"
            );
        }
        assert_eq!(
            heartbeat.due(start + Duration::from_secs(601), watermark(5, 2)),
            Some(watermark(5, 2)),
            "a change after a long idle is reported at once"
        );
    }

    /// The frame is a sealed PING with the 18-byte ctrl prefix and no seq.
    #[test]
    fn u_ping_frame_carries_the_watermark_in_the_ctrl_prefix() {
        let ring = KeyRing::derive(&[0x51; 32], &ClusterId::from_bytes([0x52; 16]))
            .unwrap_or_else(|error| panic!("key ring: {error}"));
        let nonces = NonceMinter::with_instance(7);
        let frame = ping_frame(watermark(41, 3), 1_700_000_000_000_000, &ring, &nonces)
            .unwrap_or_else(|error| panic!("ping: {error}"));

        assert_eq!(frame.header.msg_type, MsgType::PING);
        assert_eq!(frame.header.seq, Seq::UNSEQUENCED);
        assert!(frame.header.flags.contains(Flags::CTRL));
        assert!(frame.header.flags.contains(Flags::ENC));

        let mut decoder = FrameDecoder::new(Limits::default());
        decoder
            .push(
                &crate::protocol::FrameEncoder::new()
                    .encode_owned(&crate::protocol::FrameRef::new(
                        &frame.header,
                        &frame.prefix,
                        &frame.body,
                    ))
                    .unwrap_or_else(|error| panic!("encode: {error}")),
            )
            .unwrap_or_else(|error| panic!("push: {error}"));
        let decoded = decoder
            .next_frame_owned()
            .unwrap_or_else(|error| panic!("decode: {error}"))
            .expect("frame");
        let ctrl = decoded.prefix.as_ctrl().expect("ctrl prefix");
        assert_eq!(*ctrl, CtrlPrefix::new(Seq(41), 3));
        assert_eq!(ctrl.encode().len(), CtrlPrefix::ENCODED_LEN);

        let opened = Opener::new(&ring)
            .open(&decoded.header, &decoded.prefix, &decoded.body)
            .unwrap_or_else(|error| panic!("open: {error}"));
        let ping = Ping::decode(opened.as_slice(), &Limits::default())
            .unwrap_or_else(|error| panic!("ping body: {error}"));
        assert_eq!(ping.client_time, 1_700_000_000_000_000);
    }
}
