//! 1.1 `--mmap` foundation: independent SQLite schema, value types, database
//! access, base versions and directory manifests.
//!
//! Everything here is deliberately separate from the 1.0 `/private` and
//! `/public` paths. The module owns its own database file and never changes
//! the 1.0 schema, event log, protocol or FUSE behaviour.
//!
//! The pieces:
//!
//! * [`schema`] — DDL, migration and open-time pragmas.
//! * [`types`] — newtypes and records exchanged with the database.
//! * [`db`] — one writer (`BEGIN IMMEDIATE`) and independent read snapshots.
//! * [`base`] — the `(epoch, dir_seq, dir_version)` triple and canonical
//!   directory-version hashing.
//! * [`manifest`] — the full direct-entry manifest, its canonical encoding,
//!   `manifest_hash` and completeness checks.
//! * [`proto`] and [`rsync`] — the SMM1 wire format and the rsync engine.

use std::time::{SystemTime, UNIX_EPOCH};

pub mod base;
pub mod client;
pub mod db;
pub mod manifest;
pub mod proto;
pub mod rsync;
pub mod schema;
pub mod server;
pub mod shadow;
pub mod types;

#[cfg(feature = "fuse")]
pub mod fuse;

pub use base::{dir_root, empty_file_root, file_root, symlink_root};
pub use db::{MmDb, MmTx, ReadTx, WriteTx};
pub use manifest::{Manifest, ManifestError};
pub use types::*;

#[cfg(all(test, feature = "mmap-tests"))]
mod tests;

/// Every error that can cross the mm database boundary.
#[derive(Debug, thiserror::Error)]
pub enum MmError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest: {0}")]
    Manifest(#[from] ManifestError),
    #[error("unsupported mm schema version {found}; supported {supported}")]
    UnsupportedSchema { found: i64, supported: i64 },
    #[error("mm database role mismatch: stored {stored:?}, requested {requested:?}")]
    RoleMismatch { stored: MmRole, requested: MmRole },
    #[error("mm database namespace mismatch: stored {stored}, requested {requested}")]
    NamespaceMismatch { stored: String, requested: String },
    #[error("mm database is not in WAL mode: {mode}")]
    NotWal { mode: String },
    #[error("corrupt mm database: {0}")]
    Corrupt(&'static str),
    #[error("invalid value: {0}")]
    Invalid(&'static str),
    #[error("not found")]
    NotFound,
}

impl From<&'static str> for MmError {
    fn from(reason: &'static str) -> Self {
        Self::Invalid(reason)
    }
}

/// Unix milliseconds, clamped to the representable range.
///
/// The database stores timestamps as SQLite `INTEGER`, so a clock before the
/// epoch maps to zero instead of a negative value that violates the schema.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
