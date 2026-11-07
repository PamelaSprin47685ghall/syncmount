//! M4 chaos matrix: F1–F24 fault injection and watermark W1–W7.
//!
//! ```text
//! cargo test --test chaos_matrix --features testkit,chaos-tests -- --test-threads=1 --nocapture
//! ```
//!
//! Every test prints one `chaos evidence:` line. The suite never skips a
//! safety assertion; the internal M4 runner (not published) captures one log
//! per item.

#![cfg(feature = "chaos-tests")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_arguments,
    dead_code
)]

mod chaos;
