//! Full direct-entry directory manifest, canonical encoding and hashing.
//!
//! A manifest lists every direct entry of one directory: regular files,
//! symlinks and child directories. Nothing is omitted to mean "delete"; every
//! entry carries an explicit [`EntryOp`]. Child directory *contents* are never
//! part of the parent manifest.
//!
//! # Canonical encoding
//!
//! Entries are sorted by name bytes. The encoding is:
//!
//! ```text
//! entry_count_le32
//! for each entry:
//!     name_len_le32 || name
//!     || kind_u8 || op_u8
//!     || from_name_present_u8 [|| from_name_len_le32 || from_name]
//!     || ino || mode_le32 || uid_le32 || gid_le32 || mtime_ns_le64
//!     || size_le64 || file_root
//!     || content_hash_present_u8 [|| content_hash]
//!     || target_present_u8 [|| target_len_le32 || target]
//! ```
//!
//! `manifest_hash = BLAKE3 over that encoding` (no derive-key prefix, matching
//! the 1.1 design). The hash is the begin/commit idempotency key, so the
//! encoding is a wire contract and must not drift silently.

use super::base::{dir_root, symlink_root};
use super::types::{EntryKind, EntryOp, FileRecord, Hash, Ino, ManifestEntry, validate_name};
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// Why a manifest was rejected before it reached the database.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("duplicate manifest name: {0}")]
    DuplicateName(String),
    #[error("duplicate inode in manifest: {0:?}")]
    DuplicateIno(Ino),
    #[error("invalid manifest name {name}: {reason}")]
    InvalidName { name: String, reason: &'static str },
    #[error("operation {op:?} is not valid for {kind:?} entry {name}")]
    InvalidOp {
        name: String,
        kind: EntryKind,
        op: EntryOp,
    },
    #[error("PUT entry {0} is missing content_hash")]
    MissingContentHash(String),
    #[error("symlink entry {0} is missing target")]
    MissingTarget(String),
    #[error("rename entry {0} is missing from_name")]
    MissingFromName(String),
    #[error("entry {0} has an unexpected from_name")]
    UnexpectedFromName(String),
    #[error("entry {0} has an unexpected target")]
    UnexpectedTarget(String),
    #[error("entry {0} has an unexpected content_hash")]
    UnexpectedContentHash(String),
    #[error("entry {name} has a file_root that does not match its {kind:?} kind")]
    InvalidFileRoot { name: String, kind: EntryKind },
    #[error("directory entry {0} has a non-zero size")]
    DirectorySize(String),
    #[error("symlink entry {0} has a size that does not match its target")]
    SymlinkSize(String),
    #[error("entry {0} uses the root inode")]
    RootInode(String),
    #[error("entry {0} has a negative mtime")]
    NegativeMtime(String),
}

/// A complete, canonically ordered direct-entry manifest.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Manifest {
    entries: Vec<ManifestEntry>,
}

impl Manifest {
    /// Validate, sort and wrap a list of entries.
    pub fn new(mut entries: Vec<ManifestEntry>) -> Result<Self, ManifestError> {
        let mut inodes = HashSet::new();
        for entry in &entries {
            validate_entry(entry)?;
            if !inodes.insert(entry.ino) {
                return Err(ManifestError::DuplicateIno(entry.ino));
            }
        }
        entries.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
        for pair in entries.windows(2) {
            if pair[0].name == pair[1].name {
                return Err(ManifestError::DuplicateName(pair[0].name.clone()));
            }
        }
        Ok(Self { entries })
    }

    /// Build a manifest from the current rows of one directory.
    ///
    /// Every entry becomes `KEEP`; call [`Manifest::diff`] to derive the
    /// explicit operations against a base.
    pub fn from_records(records: &[FileRecord]) -> Result<Self, ManifestError> {
        Self::new(
            records
                .iter()
                .map(|record| record.manifest_entry(EntryOp::Keep))
                .collect(),
        )
    }

    /// Build a base manifest from stored entries.
    ///
    /// Base rows have no operation; every entry becomes `KEEP` and loses any
    /// stale `from_name`.
    pub fn from_base_entries(entries: Vec<ManifestEntry>) -> Result<Self, ManifestError> {
        Self::new(
            entries
                .into_iter()
                .map(|mut entry| {
                    entry.op = EntryOp::Keep;
                    entry.from_name = None;
                    entry
                })
                .collect(),
        )
    }

    /// The canonically ordered entries.
    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }

    /// Consume the manifest and return its entries.
    pub fn into_entries(self) -> Vec<ManifestEntry> {
        self.entries
    }

    /// Number of direct entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the directory has no direct entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look one entry up by name.
    pub fn get(&self, name: &str) -> Option<&ManifestEntry> {
        self.entries
            .binary_search_by(|entry| entry.name.as_str().cmp(name))
            .ok()
            .map(|index| &self.entries[index])
    }

    /// The canonical encoding described in the module contract.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.canonical_with(|bytes| out.extend_from_slice(bytes));
        out
    }

    /// `manifest_hash`, the begin/commit idempotency key.
    pub fn hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        self.canonical_with(|bytes| {
            hasher.update(bytes);
        });
        *hasher.finalize().as_bytes()
    }

    /// Feed the canonical encoding to a sink without allocating a buffer.
    fn canonical_with<F>(&self, mut feed: F)
    where
        F: FnMut(&[u8]),
    {
        assert!(
            self.entries.len() <= u32::MAX as usize,
            "manifest entry count does not fit u32"
        );
        feed(&(self.entries.len() as u32).to_le_bytes());
        for entry in &self.entries {
            feed_bytes(&mut feed, entry.name.as_bytes());
            feed(&[entry.kind.tag()]);
            feed(&[entry.op.tag()]);
            match &entry.from_name {
                Some(name) => {
                    feed(&[1]);
                    feed_bytes(&mut feed, name.as_bytes());
                }
                None => feed(&[0]),
            }
            feed(&entry.ino);
            feed(&entry.mode.to_le_bytes());
            feed(&entry.uid.to_le_bytes());
            feed(&entry.gid.to_le_bytes());
            feed(&(entry.mtime_ns as u64).to_le_bytes());
            feed(&entry.size.to_le_bytes());
            feed(&entry.file_root);
            match &entry.content_hash {
                Some(hash) => {
                    feed(&[1]);
                    feed(hash);
                }
                None => feed(&[0]),
            }
            match &entry.target {
                Some(target) => {
                    feed(&[1]);
                    feed_bytes(&mut feed, target);
                }
                None => feed(&[0]),
            }
        }
    }

    /// Names expected by the caller that this manifest does not list.
    ///
    /// The result is sorted and deduplicated. A non-empty result is
    /// `MANIFEST_INCOMPLETE`; the manifest never implies a deletion.
    pub fn missing_against<'a, I>(&self, expected: I) -> Vec<String>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let have: BTreeSet<&str> = self
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        let mut missing: Vec<String> = expected
            .into_iter()
            .filter(|name| !have.contains(name))
            .map(str::to_owned)
            .collect();
        missing.sort();
        missing.dedup();
        missing
    }

    /// Names present in this manifest that the caller did not expect.
    ///
    /// The result is sorted and deduplicated. A non-empty result is
    /// `MANIFEST_INVALID`: the manifest may not invent entries.
    pub fn unexpected_against<'a, I>(&self, expected: I) -> Vec<String>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let expected: BTreeSet<&str> = expected.into_iter().collect();
        let mut unexpected: Vec<String> = self
            .entries
            .iter()
            .filter(|entry| !expected.contains(entry.name.as_str()))
            .map(|entry| entry.name.clone())
            .collect();
        unexpected.sort();
        unexpected.dedup();
        unexpected
    }

    /// True when the manifest's name set is exactly the expected set.
    pub fn is_complete_for<'a, I>(&self, expected: I) -> bool
    where
        I: IntoIterator<Item = &'a str>,
    {
        let expected: BTreeSet<&str> = expected.into_iter().collect();
        let have: BTreeSet<&str> = self
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        expected == have
    }

    /// Derive the explicit manifest between one base and the current rows.
    ///
    /// Matching is by `ino` first (a rename), then by name. Content that is
    /// unchanged becomes `KEEP` even when attributes changed: the entry still
    /// carries the new attributes, so the server applies them without
    /// rewriting content. A kind change or content change becomes `PUT` for a
    /// file/symlink and `DIR_ADD` for a directory, which the server treats as
    /// a replacement. Base entries with no current row become `DELETE` or
    /// `DIR_REMOVE`.
    pub fn diff(base: &[ManifestEntry], current: &[ManifestEntry]) -> Result<Self, ManifestError> {
        let base_by_ino: BTreeMap<Ino, &ManifestEntry> =
            base.iter().map(|entry| (entry.ino, entry)).collect();
        let base_by_name: BTreeMap<&str, &ManifestEntry> = base
            .iter()
            .map(|entry| (entry.name.as_str(), entry))
            .collect();
        let mut used: HashSet<&str> = HashSet::new();
        let mut entries = Vec::with_capacity(current.len() + base.len());

        for entry in current {
            if let Some(old) = base_by_ino.get(&entry.ino) {
                if old.name != entry.name && old.kind == entry.kind {
                    let op = if entry.kind.is_dir() {
                        EntryOp::DirRename
                    } else {
                        EntryOp::Rename
                    };
                    entries.push(with_op(entry, op, Some(old.name.clone())));
                    used.insert(old.name.as_str());
                    continue;
                }
            }

            if let Some(old) = base_by_name.get(entry.name.as_str()) {
                used.insert(old.name.as_str());
                if old.kind != entry.kind {
                    entries.push(with_op(
                        entry,
                        if entry.kind.is_dir() {
                            EntryOp::DirAdd
                        } else {
                            EntryOp::Put
                        },
                        None,
                    ));
                    continue;
                }
                // `file_root` commits to the ordered chunk list, so it is
                // the identity of the content. `content_hash` is only the
                // transport-level whole-file check and may be absent from a
                // stored base entry.
                let same_content = old.ino == entry.ino
                    && old.file_root == entry.file_root
                    && old.size == entry.size
                    && old.target == entry.target;
                let op = if same_content || entry.kind.is_dir() {
                    EntryOp::Keep
                } else {
                    EntryOp::Put
                };
                entries.push(with_op(entry, op, None));
            } else {
                entries.push(with_op(
                    entry,
                    if entry.kind.is_dir() {
                        EntryOp::DirAdd
                    } else {
                        EntryOp::Put
                    },
                    None,
                ));
            }
        }

        for entry in base {
            if used.contains(entry.name.as_str()) {
                continue;
            }
            entries.push(with_op(
                entry,
                if entry.kind.is_dir() {
                    EntryOp::DirRemove
                } else {
                    EntryOp::Delete
                },
                None,
            ));
        }

        Self::new(entries)
    }
}

fn with_op(entry: &ManifestEntry, op: EntryOp, from_name: Option<String>) -> ManifestEntry {
    let mut out = entry.clone();
    out.op = op;
    out.from_name = from_name;
    out
}

fn validate_entry(entry: &ManifestEntry) -> Result<(), ManifestError> {
    validate_name(&entry.name).map_err(|reason| ManifestError::InvalidName {
        name: entry.name.clone(),
        reason,
    })?;
    if entry.ino == super::types::ROOT_INO {
        return Err(ManifestError::RootInode(entry.name.clone()));
    }
    if entry.mtime_ns < 0 {
        return Err(ManifestError::NegativeMtime(entry.name.clone()));
    }
    if let Some(from_name) = &entry.from_name {
        validate_name(from_name).map_err(|reason| ManifestError::InvalidName {
            name: from_name.clone(),
            reason,
        })?;
    }

    match entry.kind {
        EntryKind::Dir => {
            if !matches!(
                entry.op,
                EntryOp::Keep | EntryOp::DirAdd | EntryOp::DirRemove | EntryOp::DirRename
            ) {
                return Err(ManifestError::InvalidOp {
                    name: entry.name.clone(),
                    kind: entry.kind,
                    op: entry.op,
                });
            }
            if entry.size != 0 {
                return Err(ManifestError::DirectorySize(entry.name.clone()));
            }
            if entry.target.is_some() {
                return Err(ManifestError::UnexpectedTarget(entry.name.clone()));
            }
            if entry.content_hash.is_some() {
                return Err(ManifestError::UnexpectedContentHash(entry.name.clone()));
            }
            if entry.file_root != dir_root() {
                return Err(ManifestError::InvalidFileRoot {
                    name: entry.name.clone(),
                    kind: entry.kind,
                });
            }
        }
        EntryKind::File | EntryKind::Symlink => {
            if !matches!(
                entry.op,
                EntryOp::Keep | EntryOp::Put | EntryOp::Delete | EntryOp::Rename
            ) {
                return Err(ManifestError::InvalidOp {
                    name: entry.name.clone(),
                    kind: entry.kind,
                    op: entry.op,
                });
            }
            if entry.kind == EntryKind::File {
                if entry.target.is_some() {
                    return Err(ManifestError::UnexpectedTarget(entry.name.clone()));
                }
                if entry.op == EntryOp::Put && entry.content_hash.is_none() {
                    return Err(ManifestError::MissingContentHash(entry.name.clone()));
                }
            } else {
                if entry.content_hash.is_some() {
                    return Err(ManifestError::UnexpectedContentHash(entry.name.clone()));
                }
                let Some(target) = &entry.target else {
                    return Err(ManifestError::MissingTarget(entry.name.clone()));
                };
                if entry.size != target.len() as u64 {
                    return Err(ManifestError::SymlinkSize(entry.name.clone()));
                }
                if entry.file_root != symlink_root(target) {
                    return Err(ManifestError::InvalidFileRoot {
                        name: entry.name.clone(),
                        kind: entry.kind,
                    });
                }
            }
        }
    }

    match entry.op {
        EntryOp::Rename | EntryOp::DirRename => {
            if entry.from_name.is_none() {
                return Err(ManifestError::MissingFromName(entry.name.clone()));
            }
        }
        _ => {
            if entry.from_name.is_some() {
                return Err(ManifestError::UnexpectedFromName(entry.name.clone()));
            }
        }
    }

    Ok(())
}

fn feed_bytes<F>(feed: &mut F, bytes: &[u8])
where
    F: FnMut(&[u8]),
{
    assert!(
        bytes.len() <= u32::MAX as usize,
        "field length does not fit u32"
    );
    feed(&(bytes.len() as u32).to_le_bytes());
    feed(bytes);
}

impl std::fmt::Display for Manifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        for entry in &self.entries {
            if !first {
                f.write_str(", ")?;
            }
            first = false;
            write!(f, "{} {:?} {:?}", entry.name, entry.kind, entry.op)?;
        }
        Ok(())
    }
}
