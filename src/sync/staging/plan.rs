//! Ordered apply plan.
//!
//! The plan is a value, not an executor. Construction validates every target
//! and every staging path immediately, so an invalid plan cannot exist:
//!
//! * target paths reject reserved names, `..`, absolute paths and depth > 256;
//! * install/replace sources must be a flat `.syncmount-staging/tree/<n>.sm-tmp`.
//!
//! Execution order is fixed by [`crate::sync::staging::apply`], not by
//! insertion order: directories by ascending depth, removals by descending
//! depth, replacements, installs, then in-place attributes. This keeps every
//! intermediate path resolvable (43 §6.3).

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::store::AttrDelta;

use super::{StagingError, validate_staging, validate_target};

/// One operation in a plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyItem {
    /// Create a directory (idempotent when it already exists).
    Mkdir {
        /// Target path.
        path: PathBuf,
        /// Permission bits.
        mode: u32,
    },
    /// Remove a `LocalOnly` file or directory.
    Remove {
        /// Target path.
        path: PathBuf,
        /// `true` for `rmdir`, `false` for `unlink`.
        dir: bool,
    },
    /// Replace an existing item of a different type: old item to trash, new
    /// item into place.
    TypeReplace {
        /// Flat staging source.
        staging: PathBuf,
        /// Target path.
        target: PathBuf,
    },
    /// Rename a staged file onto its target (single-file atomic commit).
    Install {
        /// Flat staging source.
        staging: PathBuf,
        /// Target path.
        target: PathBuf,
    },
    /// Apply attributes in place (`AttrsOnly`).
    Attrs {
        /// Target path.
        path: PathBuf,
        /// Attribute changes.
        delta: AttrDelta,
    },
}

/// A validated, unordered collection of apply operations.
#[derive(Clone, Debug, Default)]
pub struct ApplyPlan {
    items: Vec<ApplyItem>,
    dirs: BTreeSet<PathBuf>,
}

impl ApplyPlan {
    /// An empty plan.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a directory creation. Repeated paths are ignored (the first
    /// mode wins; a later attribute change belongs in [`Self::push_attrs`]).
    pub fn push_mkdir(&mut self, path: PathBuf, mode: u32) -> Result<(), StagingError> {
        validate_target(&path)?;
        if self.dirs.insert(path.clone()) {
            self.items.push(ApplyItem::Mkdir { path, mode });
        }
        Ok(())
    }

    /// Append a `LocalOnly` removal.
    pub fn push_remove(&mut self, path: PathBuf, dir: bool) -> Result<(), StagingError> {
        validate_target(&path)?;
        self.items.push(ApplyItem::Remove { path, dir });
        Ok(())
    }

    /// Append a type replacement.
    pub fn push_type_replace(
        &mut self,
        staging: PathBuf,
        target: PathBuf,
    ) -> Result<(), StagingError> {
        validate_target(&target)?;
        validate_staging(&staging)?;
        self.items.push(ApplyItem::TypeReplace { staging, target });
        Ok(())
    }

    /// Append a single-file install.
    pub fn push_install(&mut self, staging: PathBuf, target: PathBuf) -> Result<(), StagingError> {
        validate_target(&target)?;
        validate_staging(&staging)?;
        self.items.push(ApplyItem::Install { staging, target });
        Ok(())
    }

    /// Append an in-place attribute change.
    pub fn push_attrs(&mut self, path: PathBuf, delta: AttrDelta) -> Result<(), StagingError> {
        validate_target(&path)?;
        self.items.push(ApplyItem::Attrs { path, delta });
        Ok(())
    }

    /// The operations, in insertion order.
    pub fn items(&self) -> &[ApplyItem] {
        &self.items
    }

    /// Number of operations.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// True when there is nothing to do.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    /// 31:M3-7
    #[test]
    fn u_staging_plan_validates_paths() {
        let mut plan = ApplyPlan::new();
        assert!(matches!(
            plan.push_install(
                PathBuf::from(".syncmount-staging/tree/0.sm-tmp"),
                PathBuf::from(".syncmount-manifest"),
            ),
            Err(StagingError::ReservedName(_))
        ));
        assert!(matches!(
            plan.push_install(PathBuf::from("elsewhere/0.sm-tmp"), PathBuf::from("f"),),
            Err(StagingError::InvalidStaging(_))
        ));
        assert!(matches!(
            plan.push_install(
                PathBuf::from(".syncmount-staging/tree/0.sm-tmp"),
                PathBuf::from("../escape"),
            ),
            Err(StagingError::InvalidTarget(_))
        ));
        assert!(plan.is_empty());
    }

    /// 31:M3-7
    #[test]
    fn u_staging_plan_dedups_directories() {
        let mut plan = ApplyPlan::new();
        plan.push_mkdir(PathBuf::from("a"), 0o755).unwrap();
        plan.push_mkdir(PathBuf::from("a"), 0o700).unwrap();
        plan.push_mkdir(PathBuf::from("a/b"), 0o755).unwrap();
        assert_eq!(plan.len(), 2);
    }
}
