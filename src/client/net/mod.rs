//! Client network helpers that survive the v2 cutover.
//!
//! The transport and the handshake live in [`crate::client::session`]; this
//! module keeps only the `STREAM_DATA` reassembly cache and the wall clock the
//! connection trace uses.

pub mod data;

pub use data::DataCache;

/// Wall clock in microseconds for the status trace.
pub(crate) fn wall_clock_us() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_micros()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
