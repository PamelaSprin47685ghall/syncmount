//! Staging and per-item application.
//!
//! The backing root is also the mountpoint (49 A5). New content is written to
//! a **flat** staging tree inside it, then moved into place with one `rename`
//! per file:
//!
//! ```text
//! .syncmount-staging/tree/<n>.sm-tmp   # new file, flat name
//! .syncmount-staging/trash/<n>         # replaced old item
//! .syncmount-staging/tmp/              # signatures and other spills
//! ```
//!
//! * [`build`] writes only the differences, `fsync`s them, and records
//!   `(staging name -> target path)`. The input is the `(path, chunk_id, blob)`
//!   stream; no manifest type is required.
//! * [`plan`] is the ordered list of operations: directories first, then
//!   `LocalOnly` removals deepest-first, then type replacements into trash,
//!   then installs.
//! * [`apply`] executes the plan. The `rename` of one staging file is that
//!   file's only visibility switch: there is no whole-tree exchange point
//!   (43 I5, C-31).
//!
//! Reserved names (`.syncmount`, `.syncmount-staging`, `.syncmount-manifest`,
//! `.audit.log`) can never be targets; validation is a type-level gate on
//! every plan item, not a convention.

pub mod apply;
pub mod build;
pub mod plan;

pub use apply::{ApplyReport, apply, purge};
pub use build::{CleanupReport, StagedFile, StagingBuild, cleanup_stale};
pub use plan::{ApplyItem, ApplyPlan};

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

use thiserror::Error;

use crate::store::backing::RootFd;
use crate::store::{Errno, Kind, STAGING_DIR, STAGING_TREE, is_reserved_name};

use super::chunk::ChunkCipherError;

/// Directory holding replaced items until the commit step.
pub const TRASH_DIR: &str = ".syncmount-staging/trash";
/// Directory for signature spills and other transient files.
pub const TMP_DIR: &str = ".syncmount-staging/tmp";
/// Suffix of a staged file.
pub const STAGE_SUFFIX: &str = ".sm-tmp";
/// Maximum path depth accepted for a target (matches the store's limit).
pub const MAX_DEPTH: usize = 256;

/// Staging and apply failures.
#[derive(Debug, Error)]
pub enum StagingError {
    /// A backing `*at` call failed.
    #[error("staging I/O: {0}")]
    Io(#[from] Errno),
    /// A chunk failed its content verification.
    #[error("staging chunk: {0}")]
    Chunk(#[from] ChunkCipherError),
    /// A target path contains a reserved internal name.
    #[error("reserved name in path: {0}")]
    ReservedName(String),
    /// A target path is absolute, empty, contains `..`, or is too deep.
    #[error("invalid target path: {0}")]
    InvalidTarget(String),
    /// A staging path is not a flat `.syncmount-staging/tree/<n>.sm-tmp`.
    #[error("invalid staging path: {0}")]
    InvalidStaging(String),
    /// A path that must be a directory is not one.
    #[error("not a directory: {0}")]
    NotADirectory(String),
    /// A staged file was already consumed.
    #[error("staged file already installed: {0}")]
    AlreadyInstalled(String),
}

/// Create a directory, accepting an existing directory.
pub(crate) fn ensure_dir(root: &RootFd, rel: &Path) -> Result<(), StagingError> {
    match root.mkdir_at(rel, 0o700) {
        Ok(()) => Ok(()),
        Err(err) if err == Errno::EEXIST => {
            let attr = root.stat_at(rel, false)?;
            if attr.kind() == Kind::Dir {
                Ok(())
            } else {
                Err(StagingError::NotADirectory(rel.display().to_string()))
            }
        }
        Err(err) => Err(err.into()),
    }
}

/// Create the three staging directories.
pub(crate) fn ensure_layout(root: &RootFd) -> Result<(), StagingError> {
    ensure_dir(root, Path::new(STAGING_DIR))?;
    ensure_dir(root, Path::new(STAGING_TREE))?;
    ensure_dir(root, Path::new(TRASH_DIR))?;
    ensure_dir(root, Path::new(TMP_DIR))?;
    Ok(())
}

/// Validate a target path relative to the backing root.
///
/// Rejects absolute paths, `.`/`..`, NUL bytes, paths deeper than
/// [`MAX_DEPTH`], and every reserved internal name. This is the single
/// reserved-name gate used by both staging and apply.
pub fn validate_target(path: &Path) -> Result<(), StagingError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(StagingError::InvalidTarget(path.display().to_string()));
    }
    let mut depth = 0usize;
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                if part.as_bytes().contains(&0) {
                    return Err(StagingError::InvalidTarget(path.display().to_string()));
                }
                if is_reserved_name(part) {
                    return Err(StagingError::ReservedName(
                        part.to_string_lossy().into_owned(),
                    ));
                }
                depth += 1;
                if depth > MAX_DEPTH {
                    return Err(StagingError::InvalidTarget(path.display().to_string()));
                }
            }
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                return Err(StagingError::InvalidTarget(path.display().to_string()));
            }
        }
    }
    if depth == 0 {
        return Err(StagingError::InvalidTarget(path.display().to_string()));
    }
    Ok(())
}

/// Validate a flat staging path: `.syncmount-staging/tree/<n>.sm-tmp`.
pub(crate) fn validate_staging(path: &Path) -> Result<(), StagingError> {
    let parts: Vec<Component<'_>> = path.components().collect();
    let valid = match parts.as_slice() {
        [
            Component::Normal(root),
            Component::Normal(tree),
            Component::Normal(name),
        ] => {
            *root == OsStr::new(STAGING_DIR)
                && *tree == OsStr::new("tree")
                && name.as_bytes().ends_with(STAGE_SUFFIX.as_bytes())
                && name.as_bytes().len() > STAGE_SUFFIX.len()
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(StagingError::InvalidStaging(path.display().to_string()))
    }
}

/// True when `rel` exists below the root.
pub(crate) fn exists(root: &RootFd, rel: &Path) -> Result<bool, StagingError> {
    match root.stat_at(rel, false) {
        Ok(_) => Ok(true),
        Err(err) if err == Errno::ENOENT => Ok(false),
        Err(err) => Err(err.into()),
    }
}

/// Remove one entry recursively. Returns the number of entries removed.
pub(crate) fn remove_entry(root: &RootFd, rel: &Path) -> Result<u64, StagingError> {
    let attr = match root.stat_at(rel, false) {
        Ok(attr) => attr,
        Err(err) if err == Errno::ENOENT => return Ok(0),
        Err(err) => return Err(err.into()),
    };
    if attr.kind() == Kind::Dir {
        let mut removed = 0u64;
        for entry in root.list_at(rel)? {
            removed = removed.saturating_add(remove_entry(root, &rel.join(entry.name))?);
        }
        root.rmdir_at(rel)?;
        Ok(removed.saturating_add(1))
    } else {
        root.unlink_at(rel)?;
        Ok(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 31:M3-7
    #[test]
    fn u_staging_target_validation() {
        assert!(validate_target(Path::new("a/b")).is_ok());
        assert!(matches!(
            validate_target(Path::new(".syncmount-staging/x")),
            Err(StagingError::ReservedName(_))
        ));
        assert!(matches!(
            validate_target(Path::new("a/.audit.log")),
            Err(StagingError::ReservedName(_))
        ));
        assert!(matches!(
            validate_target(Path::new("/abs")),
            Err(StagingError::InvalidTarget(_))
        ));
        assert!(matches!(
            validate_target(Path::new("a/../b")),
            Err(StagingError::InvalidTarget(_))
        ));
        assert!(matches!(
            validate_target(Path::new("")),
            Err(StagingError::InvalidTarget(_))
        ));
    }

    /// 31:M3-7
    #[test]
    fn u_staging_staging_path_validation() {
        assert!(validate_staging(Path::new(".syncmount-staging/tree/0.sm-tmp")).is_ok());
        assert!(validate_staging(Path::new(".syncmount-staging/tree/x")).is_err());
        assert!(validate_staging(Path::new(".syncmount-staging/tree/a/0.sm-tmp")).is_err());
        assert!(validate_staging(Path::new(".syncmount-staging/trash/0")).is_err());
        assert!(validate_staging(Path::new("tree/0.sm-tmp")).is_err());
    }
}
