//! On-disk shadow layout and the single-daemon owner lock.
//!
//! ```text
//! $STATE/mm/<namespace>/
//!   owner.lock
//!   shadow.db                 SQLite metadata (WAL)
//!   dirs/<dir_ino_hex>/       one directory of direct hard links
//!   objects/<ino_hex>/v<N>    one immutable content version
//!   staging/<dir_ino_hex>/<batch_hex>/
//!   trash/
//! ```
//!
//! A shadow directory contains only direct regular-file links. Directories and
//! symlinks live in `shadow.db`; their identity is the stable 128-bit inode,
//! never the path. Renaming a directory therefore does not move its shadow
//! directory.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, flock};

use crate::mmap::types::{BatchId, Ino};

/// Map one namespace to a single filesystem-safe directory component.
///
/// `/private-mm` becomes `private-mm`; a namespace with several components
/// joins them with `#` so the result cannot escape the state root.
pub fn namespace_component(namespace: &str) -> String {
    let trimmed = namespace.trim_start_matches('/');
    let mut out = String::with_capacity(trimmed.len());
    for character in trimmed.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
            out.push(character);
        } else if character == '/' {
            out.push('#');
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("root");
    }
    out
}

/// Lower-case hexadecimal of one 128-bit inode.
pub fn hex16(ino: &Ino) -> String {
    hex::encode(ino)
}

/// One shadow state root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowLayout {
    root: PathBuf,
}

impl ShadowLayout {
    /// `$STATE/mm/<namespace>`.
    pub fn new(state_root: impl AsRef<Path>, namespace: &str) -> Self {
        Self {
            root: state_root
                .as_ref()
                .join("mm")
                .join(namespace_component(namespace)),
        }
    }

    /// The namespace root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `shadow.db`.
    pub fn db_path(&self) -> PathBuf {
        self.root.join("shadow.db")
    }

    /// `owner.lock`.
    pub fn owner_lock_path(&self) -> PathBuf {
        self.root.join("owner.lock")
    }

    /// `dirs/`.
    pub fn dirs_root(&self) -> PathBuf {
        self.root.join("dirs")
    }

    /// `objects/`.
    pub fn objects_root(&self) -> PathBuf {
        self.root.join("objects")
    }

    /// `staging/`.
    pub fn staging_root(&self) -> PathBuf {
        self.root.join("staging")
    }

    /// `trash/`.
    pub fn trash_root(&self) -> PathBuf {
        self.root.join("trash")
    }

    /// One directory's hard-link container.
    pub fn dir_dir(&self, dir_ino: &Ino) -> PathBuf {
        self.dirs_root().join(hex16(dir_ino))
    }

    /// One directory entry hard link.
    pub fn entry_path(&self, dir_ino: &Ino, name: &str) -> PathBuf {
        self.dir_dir(dir_ino).join(name)
    }

    /// One inode's version container.
    pub fn object_dir(&self, ino: &Ino) -> PathBuf {
        self.objects_root().join(hex16(ino))
    }

    /// `objects/<ino>/v<version>`.
    pub fn object_path(&self, ino: &Ino, version: u64) -> PathBuf {
        self.object_dir(ino).join(format!("v{version}"))
    }

    /// `staging/<dir_ino>/<batch_id>/`.
    pub fn staging_dir(&self, dir_ino: &Ino, batch_id: BatchId) -> PathBuf {
        self.staging_root()
            .join(hex16(dir_ino))
            .join(batch_id.to_hex())
    }

    /// Create the immutable directory skeleton.
    pub fn prepare(&self) -> io::Result<()> {
        fs::create_dir_all(self.root())?;
        fs::create_dir_all(self.dirs_root())?;
        fs::create_dir_all(self.objects_root())?;
        fs::create_dir_all(self.staging_root())?;
        fs::create_dir_all(self.trash_root())?;
        Ok(())
    }

    /// Remove staging and trash contents left by an earlier crash.
    ///
    /// Published objects without a database row are found by
    /// [`super::Shadow::collect_orphans`], not here: this pass must stay
    /// bounded and must never touch `objects/`.
    pub fn cleanup_startup(&self) -> io::Result<()> {
        clear_dir_contents(&self.staging_root())?;
        clear_dir_contents(&self.trash_root())?;
        Ok(())
    }

    /// Create an object version file, failing when it already exists.
    pub fn create_object(&self, ino: &Ino, version: u64) -> io::Result<File> {
        fs::create_dir_all(self.object_dir(ino))?;
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(self.object_path(ino, version))
    }

    /// Open an existing object version.
    pub fn open_object(&self, ino: &Ino, version: u64) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.object_path(ino, version))
    }

    /// Open an existing object version read-only.
    pub fn open_object_read(&self, ino: &Ino, version: u64) -> io::Result<File> {
        File::open(self.object_path(ino, version))
    }

    /// Make `objects/<ino>/v<version>` visible as `dirs/<dir>/<name>`.
    ///
    /// The object link is kept, so an already-open descriptor of the old
    /// directory entry keeps the same inode after the name is replaced.
    pub fn link_entry(&self, dir_ino: &Ino, name: &str, ino: &Ino, version: u64) -> io::Result<()> {
        fs::create_dir_all(self.dir_dir(dir_ino))?;
        let target = self.entry_path(dir_ino, name);
        let object = self.object_path(ino, version);
        match fs::remove_file(&target) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        fs::hard_link(&object, &target)
    }

    /// Remove one directory entry link, ignoring a missing link.
    pub fn unlink_entry(&self, dir_ino: &Ino, name: &str) -> io::Result<()> {
        match fs::remove_file(self.entry_path(dir_ino, name)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Remove one object version, ignoring a missing file.
    pub fn remove_object(&self, ino: &Ino, version: u64) -> io::Result<()> {
        match fs::remove_file(self.object_path(ino, version)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Create one staging directory.
    pub fn create_staging(&self, dir_ino: &Ino, batch_id: BatchId) -> io::Result<PathBuf> {
        let path = self.staging_dir(dir_ino, batch_id);
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    /// Remove one staging directory and everything below it.
    pub fn remove_staging(&self, dir_ino: &Ino, batch_id: BatchId) -> io::Result<()> {
        match fs::remove_dir_all(self.staging_dir(dir_ino, batch_id)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Move a published object into `trash/` and return its unique path.
    ///
    /// Callers collect the returned paths and delete them after the database
    /// transaction commits.
    pub fn trash_object(&self, ino: &Ino, version: u64) -> io::Result<Option<PathBuf>> {
        let source = self.object_path(ino, version);
        if !source.exists() {
            return Ok(None);
        }
        let destination =
            self.trash_root()
                .join(format!("{}-v{version}-{}", hex16(ino), std::process::id()));
        fs::rename(&source, &destination)?;
        Ok(Some(destination))
    }
}

fn clear_dir_contents(path: &Path) -> io::Result<()> {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            fs::remove_dir_all(entry.path())?;
        } else {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

/// Exclusive `flock` held for the lifetime of one daemon.
///
/// The kernel releases it when the process exits, including after a crash, so
/// a stale file never prevents the next start.
#[derive(Debug)]
pub struct OwnerLock {
    _file: File,
}

impl OwnerLock {
    /// Take `owner.lock` without blocking.
    ///
    /// `WouldBlock` means another daemon already owns this namespace.
    pub fn acquire(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        flock(&file, FlockOperation::NonBlockingLockExclusive)?;
        Ok(Self { _file: file })
    }
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn namespace_is_one_safe_component() {
        assert_eq!(namespace_component("/private-mm"), "private-mm");
        assert_eq!(namespace_component("/a/b"), "a#b");
        assert_eq!(namespace_component("/"), "root");
        assert_eq!(namespace_component("/x y"), "x_y");
    }

    #[test]
    fn layout_paths_are_stable_and_inode_keyed() {
        let layout = ShadowLayout::new("/state", "/private-mm");
        assert_eq!(
            layout.root(),
            Path::new("/state/mm/private-mm"),
            "state root and namespace"
        );
        assert_eq!(
            layout.object_path(&[0xab; 16], 3).file_name().unwrap(),
            "v3"
        );
        assert_eq!(
            layout.entry_path(&[0x01; 16], "name").file_name().unwrap(),
            "name"
        );
        assert_eq!(
            layout.dir_dir(&[0x01; 16]).file_name().unwrap(),
            "01010101010101010101010101010101"
        );
    }

    #[test]
    fn prepare_and_cleanup_remove_only_staging_and_trash() {
        let dir = tempfile::tempdir().unwrap();
        let layout = ShadowLayout::new(dir.path(), "/private-mm");
        layout.prepare().unwrap();
        let object = layout.create_object(&[1; 16], 1).unwrap();
        drop(object);
        let staging = layout
            .create_staging(&[2; 16], BatchId::from_bytes([3; 16]))
            .unwrap();
        std::fs::write(staging.join("part"), b"x").unwrap();
        std::fs::write(layout.trash_root().join("old"), b"y").unwrap();

        layout.cleanup_startup().unwrap();
        assert!(layout.object_path(&[1; 16], 1).exists());
        assert!(
            !layout
                .staging_dir(&[2; 16], BatchId::from_bytes([3; 16]))
                .exists()
        );
        assert!(!layout.trash_root().join("old").exists());
    }

    #[test]
    fn hard_link_keeps_an_old_descriptor_alive_after_relink() {
        let dir = tempfile::tempdir().unwrap();
        let layout = ShadowLayout::new(dir.path(), "/private-mm");
        layout.prepare().unwrap();
        let mut first = layout.create_object(&[4; 16], 1).unwrap();
        use std::io::Write as _;
        first.write_all(b"one").unwrap();
        layout.link_entry(&[5; 16], "f", &[4; 16], 1).unwrap();
        let entry = layout.entry_path(&[5; 16], "f");
        assert_eq!(std::fs::read(&entry).unwrap(), b"one");

        let mut second = layout.create_object(&[4; 16], 2).unwrap();
        second.write_all(b"two").unwrap();
        layout.link_entry(&[5; 16], "f", &[4; 16], 2).unwrap();
        assert_eq!(std::fs::read(&entry).unwrap(), b"two");
        assert_eq!(
            std::fs::read(layout.object_path(&[4; 16], 1)).unwrap(),
            b"one"
        );
    }

    #[test]
    fn owner_lock_rejects_a_second_holder() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owner.lock");
        let first = OwnerLock::acquire(&path).unwrap();
        assert!(OwnerLock::acquire(&path).is_err());
        drop(first);
        OwnerLock::acquire(&path).unwrap();
    }
}
