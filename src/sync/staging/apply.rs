//! Execute an [`ApplyPlan`] item by item.
//!
//! Fixed order (43 §6.3, 49 A5):
//!
//! 1. directories by ascending depth (parents before children);
//! 2. `LocalOnly` removals by descending depth (children before parents),
//!    each one renamed into `trash/` so the bytes stay readable;
//! 3. type replacements: the old item goes to `trash/`, the new one into place;
//! 4. installs: one `renameat` per file, the file's only visibility switch;
//! 5. in-place attributes.
//!
//! There is no whole-tree exchange and no global commit point. A crash leaves
//! each path either old or new; `trash/` and `tree/` residue is removed by
//! [`super::cleanup_stale`] on the next boot. A `LocalOnly` removal is a
//! rename into `trash/`, never an unlink, so a cluster-wins JOIN that deleted
//! too much can still be inspected before that cleanup.
//!
//! Type replacement uses `renameat2(RENAME_EXCHANGE)` when available so the
//! target path is never absent: the staged file and the old item trade places
//! atomically, then the old item moves to trash. Filesystems without exchange
//! fall back to "old to trash, new into place" (the gap is unavoidable there).

use std::path::{Path, PathBuf};

use crate::store::backing::RootFd;
use crate::store::{AttrDelta, Errno, Kind, RenameFlags};

use super::build::StagingBuild;
use super::plan::{ApplyItem, ApplyPlan};
use super::{
    STAGE_SUFFIX, StagingError, TRASH_DIR, ensure_layout, exists, remove_entry, validate_staging,
};

/// What an apply did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApplyReport {
    /// Directories created or refreshed.
    pub dirs: u64,
    /// `LocalOnly` entries removed.
    pub removed: u64,
    /// Items replaced through trash.
    pub replaced: u64,
    /// Staged files installed.
    pub installed: u64,
    /// In-place attribute changes.
    pub attrs: u64,
    /// Old items now in `trash/`, in the order they were replaced.
    pub trash: Vec<PathBuf>,
}

impl ApplyReport {
    /// Total plan items executed.
    pub fn total(&self) -> u64 {
        self.dirs + self.removed + self.replaced + self.installed + self.attrs
    }
}

/// Apply every item in the plan.
///
/// Trash entries are kept until [`purge`] (the commit step) so the outcome is
/// observable and a crash before commit still leaves the old item on disk.
pub fn apply(root: &RootFd, plan: &ApplyPlan) -> Result<ApplyReport, StagingError> {
    ensure_layout(root)?;
    let mut report = ApplyReport::default();

    let mut dirs: Vec<(PathBuf, u32)> = Vec::new();
    let mut removes: Vec<PathBuf> = Vec::new();
    let mut replaces: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut installs: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut attrs: Vec<(PathBuf, AttrDelta)> = Vec::new();

    for item in plan.items() {
        match item {
            ApplyItem::Mkdir { path, mode } => dirs.push((path.clone(), *mode)),
            ApplyItem::Remove { path, .. } => removes.push(path.clone()),
            ApplyItem::TypeReplace { staging, target } => {
                replaces.push((staging.clone(), target.clone()));
            }
            ApplyItem::Install { staging, target } => {
                installs.push((staging.clone(), target.clone()));
            }
            ApplyItem::Attrs { path, delta } => attrs.push((path.clone(), *delta)),
        }
    }

    dirs.sort_by(|a, b| depth(&a.0).cmp(&depth(&b.0)).then_with(|| a.0.cmp(&b.0)));
    removes.sort_by(|a, b| depth(b).cmp(&depth(a)).then_with(|| a.cmp(b)));
    replaces.sort_by(|a, b| a.1.cmp(&b.1));
    installs.sort_by(|a, b| a.1.cmp(&b.1));
    attrs.sort_by(|a, b| a.0.cmp(&b.0));

    for (path, mode) in dirs {
        make_dir(root, &path, mode)?;
        report.dirs += 1;
    }

    let mut trash_seq = 0u64;
    for path in removes {
        remove_one(root, &path, &mut trash_seq, &mut report)?;
        report.removed += 1;
    }

    for (staging, target) in replaces {
        replace_one(root, &staging, &target, &mut trash_seq, &mut report)?;
    }

    for (staging, target) in installs {
        validate_staging(&staging)?;
        root.rename_at(&staging, &target, RenameFlags::NONE)?;
        report.installed += 1;
    }

    for (path, delta) in attrs {
        apply_attrs(root, &path, &delta)?;
        report.attrs += 1;
    }

    root.syncfs()?;
    Ok(report)
}

/// Remove trash entries listed by an [`ApplyReport`].
///
/// Only paths below `trash/` are accepted; anything else is rejected rather
/// than deleted.
pub fn purge(root: &RootFd, trash: &[PathBuf]) -> Result<u64, StagingError> {
    let mut removed = 0u64;
    for path in trash {
        if !path.starts_with(TRASH_DIR) {
            return Err(StagingError::InvalidStaging(path.display().to_string()));
        }
        removed = removed.saturating_add(remove_entry(root, path)?);
    }
    Ok(removed)
}

/// Convenience: finish a build and apply its installs.
pub fn apply_build(root: &RootFd, build: StagingBuild) -> Result<ApplyReport, StagingError> {
    let plan = build.into_plan()?;
    apply(root, &plan)
}

fn depth(path: &Path) -> usize {
    path.components().count()
}

fn make_dir(root: &RootFd, path: &Path, mode: u32) -> Result<(), StagingError> {
    match root.mkdir_at(path, mode) {
        Ok(()) => {}
        Err(err) if err == Errno::EEXIST => {
            let attr = root.stat_at(path, false)?;
            if attr.kind() != Kind::Dir {
                return Err(StagingError::NotADirectory(path.display().to_string()));
            }
        }
        Err(err) => return Err(err.into()),
    }
    root.chmod_at(path, mode)?;
    Ok(())
}

/// Move one `LocalOnly` item into `trash/`.
///
/// The rename keeps the bytes readable until [`super::cleanup_stale`] runs on
/// the next boot, which is the only recovery window a cluster-wins JOIN has.
/// Removals run deepest first, so a directory arrives after its children and
/// each path gets its own trash entry; a path an earlier item already moved
/// is skipped instead of being reported twice.
fn remove_one(
    root: &RootFd,
    path: &Path,
    trash_seq: &mut u64,
    report: &mut ApplyReport,
) -> Result<(), StagingError> {
    if !exists(root, path)? {
        return Ok(());
    }
    let trash = alloc_trash(root, trash_seq)?;
    match root.rename_at(path, &trash, RenameFlags::NONE) {
        Ok(()) => {
            report.trash.push(trash);
            Ok(())
        }
        Err(err) if err == Errno::ENOENT => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn replace_one(
    root: &RootFd,
    staging: &Path,
    target: &Path,
    trash_seq: &mut u64,
    report: &mut ApplyReport,
) -> Result<(), StagingError> {
    validate_staging(staging)?;
    if !exists(root, target)? {
        root.rename_at(staging, target, RenameFlags::NONE)?;
        report.installed += 1;
        return Ok(());
    }

    let trash = alloc_trash(root, trash_seq)?;
    match root.rename_at(staging, target, RenameFlags::EXCHANGE) {
        Ok(()) => {
            // The old target now sits at the staging path; move it to trash.
            root.rename_at(staging, &trash, RenameFlags::NONE)?;
        }
        Err(err) if exchange_unsupported(err) => {
            // Fallback: there is a brief window where the target is absent.
            root.rename_at(target, &trash, RenameFlags::NONE)?;
            root.rename_at(staging, target, RenameFlags::NONE)?;
        }
        Err(err) => return Err(err.into()),
    }
    report.replaced += 1;
    report.trash.push(trash);
    Ok(())
}

fn exchange_unsupported(err: Errno) -> bool {
    err == Errno::EINVAL || err == Errno::ENOSYS || err == Errno::EOPNOTSUPP
}

fn alloc_trash(root: &RootFd, seq: &mut u64) -> Result<PathBuf, StagingError> {
    loop {
        let path = Path::new(TRASH_DIR).join(format!("{seq}"));
        *seq = seq.wrapping_add(1);
        if !exists(root, &path)? {
            return Ok(path);
        }
    }
}

fn apply_attrs(root: &RootFd, path: &Path, delta: &AttrDelta) -> Result<(), StagingError> {
    if let Some(mode) = delta.mode {
        root.chmod_at(path, mode)?;
    }
    if delta.uid.is_some() || delta.gid.is_some() {
        // The manifest carries the author's uid/gid, which need not exist on
        // this host. A non-root client cannot chown to a foreign id (EPERM),
        // so the local tree takes the credentials of the process that runs
        // the client. uid/gid stay author labels in the manifest, not owners.
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        root.chown_at(path, Some(uid), Some(gid))?;
    }
    if delta.atime.is_some() || delta.mtime.is_some() {
        root.utimens_at(path, delta.atime, delta.mtime)?;
    }
    Ok(())
}

/// True when `path` looks like a staging tree file (diagnostics/tests).
pub fn is_staged_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(STAGE_SUFFIX))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::store::{RootFd, STAGING_TREE};
    use std::sync::Arc;
    use tempfile::TempDir;

    fn setup(tag: &str) -> (TempDir, Arc<RootFd>) {
        let tmp = TempDir::new().unwrap_or_else(|err| panic!("tempdir {tag}: {err}"));
        let mount = tmp.path().join("mnt");
        std::fs::create_dir(&mount).unwrap_or_else(|err| panic!("mkdir {tag}: {err}"));
        let root =
            RootFd::open_before_mount(&mount).unwrap_or_else(|err| panic!("root {tag}: {err}"));
        (tmp, Arc::new(root))
    }

    fn read(root: &RootFd, rel: &Path) -> Vec<u8> {
        let fd = root
            .open_at(rel, rustix::fs::OFlags::RDONLY, rustix::fs::Mode::empty())
            .unwrap_or_else(|err| panic!("open {}: {err}", rel.display()));
        let attr = root.stat_at(rel, false).unwrap();
        let mut out = vec![0u8; attr.size as usize];
        let mut off = 0usize;
        while off < out.len() {
            let count = rustix::io::pread(&fd, &mut out[off..], off as u64).unwrap();
            if count == 0 {
                break;
            }
            off += count;
        }
        out
    }

    /// 31:M3-7 / 43 I5
    #[test]
    fn u_staging_apply_creates_dirs_before_install() {
        let (_tmp, root) = setup("dirs");
        let mut build = StagingBuild::new(root.clone()).unwrap();
        build
            .stage_bytes(Path::new("a/b/f"), b"new file", 0o640)
            .unwrap();
        let files = build.finish().unwrap();

        let mut plan = ApplyPlan::new();
        plan.push_mkdir(PathBuf::from("a/b"), 0o755).unwrap();
        plan.push_mkdir(PathBuf::from("a"), 0o755).unwrap();
        plan.push_install(files[0].staging.clone(), files[0].target.clone())
            .unwrap();
        let report = apply(&root, &plan).unwrap();

        assert_eq!(report.dirs, 2);
        assert_eq!(report.installed, 1);
        assert_eq!(read(&root, Path::new("a/b/f")), b"new file");
        assert_eq!(
            root.stat_at(Path::new("a/b/f"), false).unwrap().perm(),
            0o640
        );
        assert!(root.list_at(Path::new(STAGING_TREE)).unwrap().is_empty());
    }

    /// 31:M3-7 / 43 I5
    #[test]
    fn u_staging_apply_removes_deepest_first() {
        let (_tmp, root) = setup("remove");
        std::fs::create_dir_all(root.mountpoint().join("a/b")).unwrap();
        std::fs::write(root.mountpoint().join("a/b/f"), b"gone").unwrap();

        let mut plan = ApplyPlan::new();
        plan.push_remove(PathBuf::from("a"), true).unwrap();
        plan.push_remove(PathBuf::from("a/b/f"), false).unwrap();
        plan.push_remove(PathBuf::from("a/b"), true).unwrap();
        let report = apply(&root, &plan).unwrap();

        assert_eq!(report.removed, 3);
        assert_eq!(report.trash.len(), 3, "every removal keeps a trash entry");
        assert_eq!(
            read(&root, &report.trash[0]),
            b"gone",
            "the deleted bytes stay readable in trash"
        );
        assert_eq!(
            root.stat_at(&report.trash[1], false).unwrap().kind(),
            Kind::Dir
        );
        assert_eq!(
            root.stat_at(&report.trash[2], false).unwrap().kind(),
            Kind::Dir
        );
        assert!(root.stat_at(Path::new("a"), false).is_err());
        assert!(root.stat_at(Path::new("a/b"), false).is_err());
        assert!(root.stat_at(Path::new("a/b/f"), false).is_err());

        assert_eq!(purge(&root, &report.trash).unwrap(), 3);
        assert!(root.list_at(Path::new(TRASH_DIR)).unwrap().is_empty());
    }

    /// 31:M3-7 / 43 I5
    #[test]
    fn u_staging_apply_type_replace_goes_to_trash() {
        let (_tmp, root) = setup("replace");
        std::fs::write(root.mountpoint().join("a"), b"old content").unwrap();

        let mut build = StagingBuild::new(root.clone()).unwrap();
        build
            .stage_bytes(Path::new("a"), b"new content", 0o644)
            .unwrap();
        let files = build.finish().unwrap();

        let mut plan = ApplyPlan::new();
        plan.push_type_replace(files[0].staging.clone(), files[0].target.clone())
            .unwrap();
        let report = apply(&root, &plan).unwrap();

        assert_eq!(report.replaced, 1);
        assert_eq!(report.trash.len(), 1);
        assert_eq!(read(&root, Path::new("a")), b"new content");
        assert_eq!(read(&root, &report.trash[0]), b"old content");
        assert!(root.list_at(Path::new(STAGING_TREE)).unwrap().is_empty());

        let removed = purge(&root, &report.trash).unwrap();
        assert_eq!(removed, 1);
        assert!(root.stat_at(&report.trash[0], false).is_err());
    }

    /// 31:M3-7 / 43 I5
    #[test]
    fn u_staging_apply_install_replaces_atomically() {
        let (_tmp, root) = setup("atomic");
        std::fs::write(root.mountpoint().join("f"), b"old").unwrap();

        let mut build = StagingBuild::new(root.clone()).unwrap();
        build.stage_bytes(Path::new("f"), b"new", 0o600).unwrap();
        let files = build.finish().unwrap();
        let mut plan = ApplyPlan::new();
        plan.push_install(files[0].staging.clone(), files[0].target.clone())
            .unwrap();
        apply(&root, &plan).unwrap();

        assert_eq!(read(&root, Path::new("f")), b"new");
        let names: Vec<_> = root
            .list_at(Path::new("."))
            .unwrap()
            .into_iter()
            .map(|entry| entry.name.to_string_lossy().into_owned())
            .collect();
        assert!(
            !names.iter().any(|name| name.ends_with(".sm-tmp")),
            "no temporary name may leak into the user tree: {names:?}"
        );
    }

    /// 31:M3-7 / 43 I5
    #[test]
    fn u_staging_apply_type_replace_directory_with_file() {
        let (_tmp, root) = setup("replace-dir");
        std::fs::create_dir(root.mountpoint().join("a")).unwrap();
        std::fs::write(root.mountpoint().join("a/child"), b"old child").unwrap();

        let mut build = StagingBuild::new(root.clone()).unwrap();
        build
            .stage_bytes(Path::new("a"), b"now a file", 0o644)
            .unwrap();
        let files = build.finish().unwrap();
        let mut plan = ApplyPlan::new();
        plan.push_type_replace(files[0].staging.clone(), files[0].target.clone())
            .unwrap();
        let report = apply(&root, &plan).unwrap();

        assert_eq!(report.replaced, 1);
        assert_eq!(read(&root, Path::new("a")), b"now a file");
        assert_eq!(
            root.stat_at(Path::new("a"), false).unwrap().kind(),
            Kind::File
        );
        assert_eq!(report.trash.len(), 1);
        assert_eq!(
            root.stat_at(&report.trash[0], false).unwrap().kind(),
            Kind::Dir
        );
        assert_eq!(read(&root, &report.trash[0].join("child")), b"old child");
    }

    /// 31:M3-7 / 43 I5
    #[test]
    fn u_staging_apply_failure_leaves_target_untouched() {
        let (_tmp, root) = setup("fail");
        let mut build = StagingBuild::new(root.clone()).unwrap();
        build
            .stage_bytes(Path::new("missing/f"), b"data", 0o644)
            .unwrap();
        let files = build.finish().unwrap();
        let mut plan = ApplyPlan::new();
        plan.push_install(files[0].staging.clone(), files[0].target.clone())
            .unwrap();

        let err = apply(&root, &plan).expect_err("missing parent must fail");
        assert!(matches!(err, StagingError::Io(Errno::ENOENT)));
        assert!(root.stat_at(Path::new("missing/f"), false).is_err());
        assert!(
            root.stat_at(&files[0].staging, false).is_ok(),
            "failed install keeps the staged file"
        );
    }

    /// 31:M3-7
    #[test]
    fn u_staging_apply_attrs_only() {
        let (_tmp, root) = setup("attrs");
        std::fs::write(root.mountpoint().join("f"), b"x").unwrap();
        let mut plan = ApplyPlan::new();
        plan.push_attrs(
            PathBuf::from("f"),
            AttrDelta {
                mode: Some(0o600),
                ..AttrDelta::default()
            },
        )
        .unwrap();
        let report = apply(&root, &plan).unwrap();
        assert_eq!(report.attrs, 1);
        assert_eq!(root.stat_at(Path::new("f"), false).unwrap().perm(), 0o600);
    }

    /// 31:M3-7
    ///
    /// A manifest from another host may name a uid/gid this host does not
    /// have. Applying it must not chown to that id (EPERM for a non-root
    /// client): the file belongs to the user running the client.
    #[test]
    fn u_staging_apply_attrs_keeps_local_owner() {
        use std::os::unix::fs::MetadataExt;

        let (_tmp, root) = setup("attrs-owner");
        std::fs::write(root.mountpoint().join("f"), b"x").unwrap();

        let euid = rustix::process::geteuid().as_raw();
        let egid = rustix::process::getegid().as_raw();
        let foreign_uid = euid.wrapping_add(1);
        let foreign_gid = egid.wrapping_add(1);
        assert_ne!(foreign_uid, euid);
        assert_ne!(foreign_gid, egid);

        let mut plan = ApplyPlan::new();
        plan.push_attrs(
            PathBuf::from("f"),
            AttrDelta {
                uid: Some(foreign_uid),
                gid: Some(foreign_gid),
                ..AttrDelta::default()
            },
        )
        .unwrap();
        let report = apply(&root, &plan).unwrap();
        assert_eq!(report.attrs, 1);

        let meta = std::fs::metadata(root.mountpoint().join("f")).unwrap();
        assert_eq!(meta.uid(), euid, "file must belong to the client user");
        assert_eq!(meta.gid(), egid, "file must belong to the client group");
    }

    /// 31:M3-7
    #[test]
    fn u_staging_purge_rejects_outside_paths() {
        let (_tmp, root) = setup("purge");
        let err = purge(&root, &[PathBuf::from("user-file")]).expect_err("must reject");
        assert!(matches!(err, StagingError::InvalidStaging(_)));
    }
}
