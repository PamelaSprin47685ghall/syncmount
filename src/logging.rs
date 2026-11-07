//! Log initialisation: text or JSON, filtered by `--log-level`/`RUST_LOG`.
//!
//! Precedence, highest first (27 §2): `--log-level`, `RUST_LOG`,
//! `SYNCMOUNT_LOG`, then `info`. This module only installs the subscriber; it
//! never writes into the FUSE mountpoint and never emits key material.

use clap::ValueEnum;
use tracing_subscriber::{EnvFilter, fmt};

/// Environment variable carrying an `EnvFilter` directive.
pub const ENV_RUST_LOG: &str = "RUST_LOG";

/// Environment variable carrying the syncmount-specific filter.
pub const ENV_SYNCMOUNT_LOG: &str = "SYNCMOUNT_LOG";

/// Log rendering format selected by `--log-format`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    /// Human-readable text.
    #[default]
    #[value(alias = "pretty")]
    Text,
    /// Newline-delimited JSON.
    Json,
}

/// Failure to install the global subscriber.
#[derive(Debug, thiserror::Error)]
#[error("failed to install tracing subscriber: {0}")]
pub struct InitError(String);

/// Install the global subscriber with the environment-derived filter.
///
/// Installing twice is an error: a process owns exactly one global subscriber.
pub fn init(format: LogFormat) -> Result<(), InitError> {
    init_with(format, None)
}

/// Install the global subscriber with an explicit `--log-level` override.
///
/// The precedence is `level`, then `RUST_LOG`, then `SYNCMOUNT_LOG`, then
/// `info`. An invalid directive is a startup error rather than a silent
/// fallback: a typo in a deployment unit must be visible.
pub fn init_with(format: LogFormat, level: Option<&str>) -> Result<(), InitError> {
    let filter = build_filter(level)?;

    let installed = match format {
        LogFormat::Text => fmt().with_env_filter(filter).with_target(false).try_init(),
        LogFormat::Json => fmt()
            .json()
            .with_env_filter(filter)
            .with_target(false)
            .try_init(),
    };

    installed.map_err(|err| InitError(err.to_string()))
}

fn build_filter(level: Option<&str>) -> Result<EnvFilter, InitError> {
    let directive = level
        .map(str::to_owned)
        .or_else(|| std::env::var(ENV_RUST_LOG).ok())
        .or_else(|| std::env::var(ENV_SYNCMOUNT_LOG).ok())
        .unwrap_or_else(|| "info".to_owned());
    EnvFilter::try_new(&directive).map_err(|err| InitError(format!("invalid log filter: {err}")))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn u_log_format_accepts_pretty_as_text() {
        use clap::ValueEnum;
        assert_eq!(
            LogFormat::from_str("pretty", false).expect("pretty alias"),
            LogFormat::Text
        );
        assert_eq!(
            LogFormat::from_str("json", false).expect("json"),
            LogFormat::Json
        );
    }

    #[test]
    fn u_log_filter_priority_is_level_then_env() {
        assert!(build_filter(Some("warn")).is_ok());
        assert!(
            build_filter(Some("syncmount=banana")).is_err(),
            "an invalid level must fail startup, not degrade silently"
        );
    }
}
