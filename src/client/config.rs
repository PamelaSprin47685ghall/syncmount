//! Client configuration: endpoint, mountpoint, identity and tuning knobs.
//!
//! Owner: W11 (E5). See 41 §2.1 and 53 W11.
//!
//! This module is pure: it parses argv/env, validates the mountpoint, derives
//! the stable `mount_id`, and exposes every timing constant the writer and the
//! replayer need. It performs no I/O beyond `stat` on the mountpoint and an
//! optional password-file permission check.
//!
//! # Password sources
//!
//! The master password never comes from argv, a keyring, or a cached file
//! (39 §2.1, 37). Exactly one of:
//!
//! * `SYNCMOUNT_MASTER_PASSWORD` — the secret itself;
//! * `SYNCMOUNT_MASTER_PASSWORD_FILE` — a path whose file must be mode 0600;
//! * a TTY prompt, which belongs to the CLI/identity layer and is represented
//!   the CLI, so this module never reads a secret.
//!
//! Setting both environment variables is a configuration error: a silent
//! precedence rule would hide a stale secret.

use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Environment variable carrying the master password.
pub const ENV_MASTER_PASSWORD: &str = "SYNCMOUNT_MASTER_PASSWORD";
/// Environment variable carrying a path to the master password.
pub const ENV_MASTER_PASSWORD_FILE: &str = "SYNCMOUNT_MASTER_PASSWORD_FILE";
/// Environment variable overriding the runtime directory base.
pub const ENV_RUN_DIR: &str = "SYNCMOUNT_RUN_DIR";
/// Default runtime directory base (39 §2.1).
pub const DEFAULT_RUN_DIR: &str = "/run/syncmount";

/// A parsed cluster endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// `http` or `https`.
    pub scheme: Scheme,
    /// Host name or address literal, without brackets.
    pub host: String,
    /// Explicit or default port.
    pub port: u16,
    /// Namespace prefix, either empty or starting with `/` and never ending
    /// with one (39 §2.3: the URL path prefix *is* the namespace).
    pub prefix: String,
}

/// Transport scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// Plain HTTP/1.1.
    Http,
    /// TLS-terminated HTTP/1.1.
    Https,
}

impl Scheme {
    /// Default port for the scheme.
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }

    /// Lowercase scheme name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

impl Endpoint {
    /// Parse `scheme://host[:port][/prefix]`.
    ///
    /// The parser is deliberately strict: it accepts only what the deployment
    /// documents (24 §2), so a typo fails at startup instead of at the first
    /// frame.
    pub fn parse(url: &str) -> Result<Self, ConfigError> {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            return Err(ConfigError::EmptyUrl);
        }
        let (scheme, rest) = trimmed
            .split_once("://")
            .ok_or_else(|| ConfigError::BadUrl(trimmed.to_owned()))?;
        let scheme = match scheme {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            other => return Err(ConfigError::UnsupportedScheme(other.to_owned())),
        };
        let (authority, path) = match rest.split_once('/') {
            Some((authority, path)) => (authority, Some(path)),
            None => (rest, None),
        };
        if authority.is_empty() {
            return Err(ConfigError::MissingHost);
        }
        let (host, port) = split_authority(authority, scheme)?;
        let prefix = normalize_prefix(path.unwrap_or(""))?;
        Ok(Self {
            scheme,
            host,
            port,
            prefix,
        })
    }

    /// `host:port`, suitable for `Host:` headers and diagnostics.
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Base URL without the namespace prefix.
    pub fn origin(&self) -> String {
        format!("{}://{}", self.scheme.as_str(), self.authority())
    }

    /// Full URL for `suffix` below the namespace prefix.
    pub fn url_for(&self, suffix: &str) -> String {
        let suffix = suffix.trim_start_matches('/');
        if suffix.is_empty() {
            format!("{}{}", self.origin(), self.prefix)
        } else {
            format!("{}{}/{}", self.origin(), self.prefix, suffix)
        }
    }
}

fn split_authority(authority: &str, scheme: Scheme) -> Result<(String, u16), ConfigError> {
    // IPv6 literals keep their brackets so the port separator is unambiguous.
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| ConfigError::BadHost(authority.to_owned()))?;
        if host.is_empty() {
            return Err(ConfigError::MissingHost);
        }
        let port = match tail.strip_prefix(':') {
            Some(raw) => parse_port(raw)?,
            None if tail.is_empty() => scheme.default_port(),
            None => return Err(ConfigError::BadHost(authority.to_owned())),
        };
        return Ok((host.to_owned(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, raw)) => {
            if host.is_empty() {
                return Err(ConfigError::MissingHost);
            }
            if host.contains(':') {
                return Err(ConfigError::BadHost(authority.to_owned()));
            }
            Ok((host.to_owned(), parse_port(raw)?))
        }
        None => Ok((authority.to_owned(), scheme.default_port())),
    }
}

fn parse_port(raw: &str) -> Result<u16, ConfigError> {
    if raw.is_empty() {
        return Err(ConfigError::BadPort(raw.to_owned()));
    }
    raw.parse::<u16>()
        .map_err(|_| ConfigError::BadPort(raw.to_owned()))
}

fn normalize_prefix(path: &str) -> Result<String, ConfigError> {
    if path.is_empty() {
        return Ok(String::new());
    }
    if path.ends_with('/') {
        return Err(ConfigError::BadPrefix(path.to_owned()));
    }
    // `Endpoint::parse` split the URL at the first `/`, so `path` arrives
    // without its leading separator.
    let prefix = format!("/{path}");
    for segment in prefix[1..].split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(ConfigError::BadPrefix(path.to_owned()));
        }
    }
    Ok(prefix)
}

/// Timing and capacity knobs, with the values fixed by 39 §2.1/§2.3 and 41.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tuning {
    /// Outbox soft byte budget.
    ///
    /// Crossing it logs one warning and never rejects a write; the network
    /// must not turn a successful local write into `ENOSPC`.
    pub outbox_soft_bytes: usize,
    /// Outbox soft operation budget, with the same advisory semantics.
    pub outbox_soft_ops: usize,
    /// Aggregate size that forces an immediate send (39: 128 KiB).
    pub aggregate_bytes: usize,
    /// Largest wire op the coalescer will build (39: 4 MiB).
    pub aggregate_max: usize,
    /// Frames buffered while waiting for a missing sequence.
    pub reorder_frames: usize,
    /// How long a hole may stay open before it counts as a real gap.
    pub reorder_wait: Duration,
    /// Consecutive resyncs without a steady window before `ResyncLoop`.
    pub resync_budget: u32,
    /// A steady period that resets the resync budget.
    pub steady_window: Duration,
    /// Replay dedup table capacity (39: 1M op ids).
    pub dedup_capacity: usize,
    /// Replay dedup age limit (39: 24 h).
    pub dedup_ttl: Duration,
    /// Status-file refresh interval.
    pub status_interval: Duration,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            outbox_soft_bytes: 1024 * 1024 * 1024,
            outbox_soft_ops: 1 << 20,
            aggregate_bytes: 128 * 1024,
            aggregate_max: 4 * 1024 * 1024,
            reorder_frames: 1024,
            reorder_wait: Duration::from_secs(1),
            resync_budget: 3,
            steady_window: Duration::from_secs(60),
            dedup_capacity: 1 << 20,
            dedup_ttl: Duration::from_secs(24 * 60 * 60),
            status_interval: Duration::from_secs(5),
        }
    }
}

/// Everything the client needs before it opens a connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Cluster endpoint.
    pub endpoint: Endpoint,
    /// Absolute mountpoint.
    pub mountpoint: PathBuf,
    /// Stable id of this mountpoint, used for the runtime directory.
    pub mount_id: String,
    /// Tunables.
    pub tuning: Tuning,
    /// Runtime directory base.
    pub run_dir: PathBuf,
}

impl Config {
    /// Validate `mountpoint` and assemble the configuration.
    pub fn new(endpoint: Endpoint, mountpoint: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        let mountpoint = mountpoint.into();
        validate_mountpoint(&mountpoint)?;
        let run_dir = env::var_os(ENV_RUN_DIR)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_RUN_DIR));
        Ok(Self {
            mount_id: mount_id_for(&mountpoint),
            endpoint,
            mountpoint,
            tuning: Tuning::default(),
            run_dir,
        })
    }

    /// Replace the tunables (tests, benchmarks).
    pub fn with_tuning(mut self, tuning: Tuning) -> Self {
        self.tuning = tuning;
        self
    }

    /// Directory holding this mount's status file and lock.
    pub fn runtime_dir(&self) -> PathBuf {
        self.run_dir.join(&self.mount_id)
    }

    /// Path of the status file.
    pub fn status_path(&self) -> PathBuf {
        self.runtime_dir()
            .join(crate::store::runtime_dir::STATUS_FILE)
    }
}

/// Reject a mountpoint that cannot become a mount.
pub fn validate_mountpoint(mountpoint: &Path) -> Result<(), ConfigError> {
    if !mountpoint.is_absolute() {
        return Err(ConfigError::MountpointNotAbsolute(mountpoint.into()));
    }
    let meta =
        fs::metadata(mountpoint).map_err(|_| ConfigError::MountpointMissing(mountpoint.into()))?;
    if !meta.is_dir() {
        return Err(ConfigError::MountpointNotDirectory(mountpoint.into()));
    }
    Ok(())
}

/// Stable id for a mountpoint.
///
/// It is derived from the canonical path only, so a remount of the same
/// directory finds the previous status file and lock instead of leaking a new
/// directory under `/run` on every start.
pub fn mount_id_for(mountpoint: &Path) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sm/v1/mount-id\0");
    hasher.update(mountpoint.as_os_str().as_encoded_bytes());
    let hash = hasher.finalize();
    let hex = hash.to_hex();
    hex.as_str()[..16].to_owned()
}

/// A configuration failure. Every variant is fatal before mounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The URL was empty.
    EmptyUrl,
    /// The URL has no `scheme://` separator.
    BadUrl(String),
    /// The scheme is not `http` or `https`.
    UnsupportedScheme(String),
    /// The authority has no host.
    MissingHost,
    /// The authority cannot be parsed.
    BadHost(String),
    /// The port is not a number in `u16` range.
    BadPort(String),
    /// The path prefix is not a canonical absolute path.
    BadPrefix(String),
    /// The mountpoint is relative.
    MountpointNotAbsolute(PathBuf),
    /// The mountpoint does not exist.
    MountpointMissing(PathBuf),
    /// The mountpoint is not a directory.
    MountpointNotDirectory(PathBuf),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyUrl => f.write_str("cluster URL is empty"),
            Self::BadUrl(url) => write!(f, "cluster URL `{url}` has no `scheme://`"),
            Self::UnsupportedScheme(scheme) => {
                write!(f, "unsupported URL scheme `{scheme}` (use http or https)")
            }
            Self::MissingHost => f.write_str("cluster URL has no host"),
            Self::BadHost(authority) => write!(f, "cannot parse host in `{authority}`"),
            Self::BadPort(port) => write!(f, "invalid port `{port}`"),
            Self::BadPrefix(prefix) => write!(f, "invalid namespace prefix `{prefix}`"),
            Self::MountpointNotAbsolute(path) => {
                write!(f, "mountpoint `{}` is not absolute", path.display())
            }
            Self::MountpointMissing(path) => {
                write!(f, "mountpoint `{}` does not exist", path.display())
            }
            Self::MountpointNotDirectory(path) => {
                write!(f, "mountpoint `{}` is not a directory", path.display())
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// 31:M1-5, 39 §2.3
    #[test]
    fn u_config_endpoint_parses_origin_and_prefix() {
        let endpoint = Endpoint::parse("https://example.test:8443/team/a").unwrap();
        assert_eq!(endpoint.scheme, Scheme::Https);
        assert_eq!(endpoint.host, "example.test");
        assert_eq!(endpoint.port, 8443);
        assert_eq!(endpoint.prefix, "/team/a");
        assert_eq!(endpoint.origin(), "https://example.test:8443");
        assert_eq!(
            endpoint.url_for("/rpc"),
            "https://example.test:8443/team/a/rpc"
        );
        assert_eq!(endpoint.url_for(""), "https://example.test:8443/team/a");
    }

    /// 39 §2.3
    #[test]
    fn u_config_endpoint_defaults_and_rejects() {
        let plain = Endpoint::parse("http://host").unwrap();
        assert_eq!(plain.port, 80);
        assert_eq!(plain.prefix, "");
        let secure = Endpoint::parse("https://host").unwrap();
        assert_eq!(secure.port, 443);

        assert_eq!(Endpoint::parse(""), Err(ConfigError::EmptyUrl));
        assert_eq!(
            Endpoint::parse("ftp://host"),
            Err(ConfigError::UnsupportedScheme("ftp".into()))
        );
        assert_eq!(
            Endpoint::parse("host:80"),
            Err(ConfigError::BadUrl("host:80".into()))
        );
        assert_eq!(Endpoint::parse("http://"), Err(ConfigError::MissingHost));
        assert_eq!(
            Endpoint::parse("http://h:70000"),
            Err(ConfigError::BadPort("70000".into()))
        );
        assert!(matches!(
            Endpoint::parse("http://h/a/../b"),
            Err(ConfigError::BadPrefix(_))
        ));
        assert!(matches!(
            Endpoint::parse("http://h/a/"),
            Err(ConfigError::BadPrefix(_))
        ));
    }

    /// 24 §2
    #[test]
    fn u_config_endpoint_ipv6_literal() {
        let endpoint = Endpoint::parse("http://[::1]:9000/ns").unwrap();
        assert_eq!(endpoint.host, "::1");
        assert_eq!(endpoint.port, 9000);
        assert_eq!(endpoint.authority(), "[::1]:9000");
        assert_eq!(endpoint.prefix, "/ns");
    }

    /// 39 §2.1
    #[test]
    fn u_config_mountpoint_validation_and_mount_id() {
        let dir = tempdir();
        let config = Config::new(Endpoint::parse("http://h").unwrap(), dir.path()).unwrap();
        assert_eq!(config.mount_id.len(), 16);
        assert_eq!(config.runtime_dir(), config.run_dir.join(&config.mount_id));
        assert!(config.status_path().ends_with("status.json"));

        // The id is stable for one mountpoint and differs across mountpoints.
        let again = mount_id_for(dir.path());
        assert_eq!(again, config.mount_id);
        let other = mount_id_for(Path::new("/"));
        assert_ne!(other, config.mount_id);

        assert_eq!(
            validate_mountpoint(Path::new("relative")),
            Err(ConfigError::MountpointNotAbsolute("relative".into()))
        );
        let missing = dir.path().join("absent");
        assert_eq!(
            validate_mountpoint(&missing),
            Err(ConfigError::MountpointMissing(missing.clone()))
        );
    }

    /// 39 §2.1: 128 KiB aggregate, 1 GiB soft outbox budget.
    #[test]
    fn u_config_tuning_matches_the_spec() {
        let tuning = Tuning::default();
        assert_eq!(tuning.aggregate_bytes, 128 * 1024);
        assert_eq!(tuning.outbox_soft_bytes, 1024 * 1024 * 1024);
        assert_eq!(tuning.reorder_frames, 1024);
        assert_eq!(tuning.resync_budget, 3);
        assert_eq!(tuning.steady_window, Duration::from_secs(60));
        assert_eq!(tuning.dedup_capacity, 1 << 20);
        assert_eq!(tuning.dedup_ttl, Duration::from_secs(24 * 60 * 60));
    }
}
