//! Manifest translation, canonical hashing and begin-time validation.
//!
//! The wire entries are not trusted. This module:
//!
//! * reproduces the canonical manifest encoding for `manifest_hash`;
//! * assigns missing client inodes while refusing the root inode;
//! * checks the strict completeness rule: every direct entry that exists on
//!   the server is covered by a manifest entry, a rename source or a delete;
//! * converts a begin manifest into the final `Manifest` used for
//!   `dir_version`, base storage and the `UPLOAD_PLAN`.

use std::collections::{HashMap, HashSet};

use crate::mmap::base;
use crate::mmap::proto::{Entry as WireEntry, EntryOp as WireOp, PlanAction, PlanItem, UploadMode};
use crate::mmap::types::{
    DirSeq, EntryKind, EntryOp, FileRecord, Hash, Ino, LockRecord, ManifestEntry, ROOT_INO,
};
use crate::mmap::{Manifest, ManifestError};

use super::{Fault, child_path, path_is_within};
use crate::mmap::proto::ErrorCode;

/// `BLAKE3` over the canonical manifest bytes of typed entries.
///
/// This is byte-for-byte the encoding in `mmap::manifest`, including its sort
/// order, so a hash computed here equals [`Manifest::hash`] whenever the
/// entries would pass [`Manifest::new`].
pub fn manifest_hash(entries: &[ManifestEntry]) -> Hash {
    let mut sorted: Vec<&ManifestEntry> = entries.iter().collect();
    sorted.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(sorted.len() as u32).to_le_bytes());
    for entry in sorted {
        feed_bytes(&mut hasher, entry.name.as_bytes());
        hasher.update(&[entry.kind.tag()]);
        hasher.update(&[entry.op.tag()]);
        match &entry.from_name {
            Some(name) => {
                hasher.update(&[1]);
                feed_bytes(&mut hasher, name.as_bytes());
            }
            None => {
                hasher.update(&[0]);
            }
        }
        hasher.update(&entry.ino);
        hasher.update(&entry.mode.to_le_bytes());
        hasher.update(&entry.uid.to_le_bytes());
        hasher.update(&entry.gid.to_le_bytes());
        hasher.update(&(entry.mtime_ns as u64).to_le_bytes());
        hasher.update(&entry.size.to_le_bytes());
        hasher.update(&entry.file_root);
        match &entry.content_hash {
            Some(hash) => {
                hasher.update(&[1]);
                hasher.update(hash);
            }
            None => {
                hasher.update(&[0]);
            }
        }
        match &entry.target {
            Some(target) => {
                hasher.update(&[1]);
                feed_bytes(&mut hasher, target);
            }
            None => {
                hasher.update(&[0]);
            }
        }
    }
    *hasher.finalize().as_bytes()
}

/// The manifest hash a client computes over its wire entries.
///
/// Missing inodes encode as zero; missing directory and symlink roots encode
/// as their canonical roots, and a missing file root as zero. A client that
/// uses [`crate::mmap::types::ManifestEntry`] with all fields present gets the
/// same bytes.
pub fn wire_manifest_hash(entries: &[WireEntry]) -> Result<Hash, Fault> {
    let typed: Vec<ManifestEntry> = entries
        .iter()
        .map(wire_entry_for_hash)
        .collect::<Result<_, _>>()?;
    Ok(manifest_hash(&typed))
}

fn wire_entry_for_hash(entry: &WireEntry) -> Result<ManifestEntry, Fault> {
    let mtime_ns = i64::try_from(entry.mtime_ns)
        .map_err(|_| Fault::detail(ErrorCode::ManifestInvalid, "mtime overflows i64"))?;
    let file_root = entry.file_root.unwrap_or_else(|| match entry.kind {
        crate::mmap::proto::EntryKind::Dir => base::dir_root(),
        crate::mmap::proto::EntryKind::Symlink => match &entry.target {
            Some(target) => base::symlink_root(target),
            None => [0u8; 32],
        },
        crate::mmap::proto::EntryKind::File => [0u8; 32],
    });
    Ok(ManifestEntry {
        name: entry.name.clone(),
        ino: entry.ino.unwrap_or([0u8; 16]),
        kind: kind(entry.kind),
        op: op(entry.op),
        from_name: entry.from_name.clone(),
        mode: entry.mode,
        uid: entry.uid,
        gid: entry.gid,
        mtime_ns,
        size: entry.size,
        file_root,
        content_hash: entry.content_hash,
        target: entry.target.clone(),
    })
}

fn kind(kind: crate::mmap::proto::EntryKind) -> EntryKind {
    match kind {
        crate::mmap::proto::EntryKind::File => EntryKind::File,
        crate::mmap::proto::EntryKind::Symlink => EntryKind::Symlink,
        crate::mmap::proto::EntryKind::Dir => EntryKind::Dir,
    }
}

fn op(op: WireOp) -> EntryOp {
    match op {
        WireOp::Keep => EntryOp::Keep,
        WireOp::Put => EntryOp::Put,
        WireOp::Delete => EntryOp::Delete,
        WireOp::Rename => EntryOp::Rename,
        WireOp::DirAdd => EntryOp::DirAdd,
        WireOp::DirRemove => EntryOp::DirRemove,
        WireOp::DirRename => EntryOp::DirRename,
    }
}

fn is_rename(op: WireOp) -> bool {
    matches!(op, WireOp::Rename | WireOp::DirRename)
}

/// Convert wire entries into typed entries, assigning missing inodes.
///
/// The result is sorted by name bytes, which is also the index space used by
/// `UPLOAD_COMMIT` instructions.
pub fn assign_entries(
    entries: &[WireEntry],
    current: &[FileRecord],
) -> Result<Vec<ManifestEntry>, Fault> {
    let mut reserved: HashSet<Ino> = current.iter().map(|record| record.ino).collect();
    reserved.insert(ROOT_INO);
    let by_name: HashMap<&str, &FileRecord> = current
        .iter()
        .map(|record| (record.name.as_str(), record))
        .collect();
    let mut assigned = Vec::with_capacity(entries.len());
    let mut inos = HashSet::new();

    for entry in entries {
        entry
            .validate_manifest()
            .map_err(|error| Fault::detail(error.error_code(), error.to_string()))?;
        let inherited = match (entry.op, entry.kind) {
            (WireOp::Keep, crate::mmap::proto::EntryKind::Dir) => {
                by_name.get(entry.name.as_str()).map(|record| record.ino)
            }
            (WireOp::DirRename, crate::mmap::proto::EntryKind::Dir) => entry
                .from_name
                .as_deref()
                .and_then(|name| by_name.get(name))
                .map(|record| record.ino),
            _ => None,
        };
        if let (Some(provided), Some(inherited)) = (entry.ino, inherited) {
            if provided != inherited {
                return Err(Fault::detail(
                    ErrorCode::ManifestInvalid,
                    "directory entry inode differs from the current directory",
                ));
            }
        }
        let ino = entry
            .ino
            .or(inherited)
            .unwrap_or_else(|| random_ino(&mut reserved));
        if ino == ROOT_INO {
            return Err(Fault::detail(
                ErrorCode::ManifestInvalid,
                "entry uses the root inode",
            ));
        }
        if !inos.insert(ino) {
            return Err(Fault::detail(
                ErrorCode::ManifestInvalid,
                "duplicate inode in manifest",
            ));
        }
        reserved.insert(ino);
        let mtime_ns = i64::try_from(entry.mtime_ns)
            .map_err(|_| Fault::detail(ErrorCode::ManifestInvalid, "mtime overflows i64"))?;
        let file_root = match entry.kind {
            crate::mmap::proto::EntryKind::Dir => {
                let root = base::dir_root();
                if let Some(provided) = entry.file_root {
                    if provided != root {
                        return Err(Fault::detail(
                            ErrorCode::ManifestInvalid,
                            "directory file_root is not the canonical dir root",
                        ));
                    }
                }
                root
            }
            crate::mmap::proto::EntryKind::Symlink => {
                let target = entry.target.as_deref().ok_or_else(|| {
                    Fault::detail(ErrorCode::ManifestInvalid, "symlink entry lacks a target")
                })?;
                let root = base::symlink_root(target);
                if let Some(provided) = entry.file_root {
                    if provided != root {
                        return Err(Fault::detail(
                            ErrorCode::ManifestInvalid,
                            "symlink file_root does not match its target",
                        ));
                    }
                }
                root
            }
            crate::mmap::proto::EntryKind::File => match entry.file_root {
                Some(root) => root,
                None if entry.op == WireOp::Delete => [0u8; 32],
                None => {
                    return Err(Fault::detail(
                        ErrorCode::ManifestInvalid,
                        "regular file entry lacks file_root",
                    ));
                }
            },
        };
        assigned.push(ManifestEntry {
            name: entry.name.clone(),
            ino,
            kind: kind(entry.kind),
            op: op(entry.op),
            from_name: entry.from_name.clone(),
            mode: entry.mode,
            uid: entry.uid,
            gid: entry.gid,
            mtime_ns,
            size: entry.size,
            file_root,
            content_hash: entry.content_hash,
            target: entry.target.clone(),
        });
    }

    assigned.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    Ok(assigned)
}

fn random_ino(reserved: &mut HashSet<Ino>) -> Ino {
    loop {
        let ino = rand::random::<[u8; 16]>();
        if ino != ROOT_INO && !reserved.contains(&ino) {
            reserved.insert(ino);
            return ino;
        }
    }
}

/// Check the strict direct-entry completeness and per-entry transition rules.
///
/// A missing name is `MANIFEST_INCOMPLETE`; an operation that contradicts the
/// current row is `MANIFEST_INVALID`; a client inode used by another name is
/// `INO_CONFLICT`; a rename over a live name is `NAME_CONFLICT`.
pub fn validate_entries(
    current: &[FileRecord],
    entries: &[WireEntry],
    locks: &[LockRecord],
    dir_path: &str,
) -> Result<(), Fault> {
    let by_name: HashMap<&str, &FileRecord> = current
        .iter()
        .map(|record| (record.name.as_str(), record))
        .collect();
    let by_ino: HashMap<Ino, &FileRecord> =
        current.iter().map(|record| (record.ino, record)).collect();
    let names: HashSet<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
    let renamed_away: HashSet<&str> = entries
        .iter()
        .filter(|entry| is_rename(entry.op))
        .filter_map(|entry| entry.from_name.as_deref())
        .collect();

    let mut missing: Vec<String> = current
        .iter()
        .filter(|record| {
            !names.contains(record.name.as_str()) && !renamed_away.contains(record.name.as_str())
        })
        .map(|record| record.name.clone())
        .collect();
    missing.sort();
    missing.dedup();
    if !missing.is_empty() {
        return Err(Fault::manifest_incomplete(missing));
    }

    let mut sources = HashSet::new();
    for entry in entries {
        let existing = by_name.get(entry.name.as_str()).copied();
        if let (Some(ino), Some(record)) = (entry.ino, existing) {
            if ino == record.ino
                && kind(entry.kind) != record.kind
                && !matches!(entry.op, WireOp::Delete | WireOp::DirRemove)
            {
                return Err(invalid("a kind change needs a new inode"));
            }
        }
        if let Some(ino) = entry.ino {
            if let Some(owner) = by_ino.get(&ino) {
                let same_name = owner.name == entry.name;
                let is_source = entry.from_name.as_deref() == Some(owner.name.as_str());
                if !same_name && !is_source {
                    return Err(Fault::ino_conflict());
                }
            }
        }

        match entry.op {
            WireOp::Delete => {
                let Some(record) = existing else {
                    return Err(invalid("DELETE names an absent entry"));
                };
                if record.kind.is_dir() {
                    return Err(invalid("DELETE targets a directory"));
                }
                if kind(entry.kind) != record.kind {
                    return Err(invalid("DELETE kind differs from the current entry"));
                }
            }
            WireOp::DirRemove => {
                let Some(record) = existing else {
                    return Err(invalid("DIR_REMOVE names an absent entry"));
                };
                if !record.kind.is_dir() {
                    return Err(invalid("DIR_REMOVE targets a non-directory"));
                }
            }
            WireOp::Rename | WireOp::DirRename => {
                let from = entry
                    .from_name
                    .as_deref()
                    .ok_or_else(|| invalid("rename lacks from_name"))?;
                if !sources.insert(from.to_owned()) {
                    return Err(invalid("two entries rename the same source"));
                }
                let Some(source) = by_name.get(from).copied() else {
                    return Err(invalid("rename source is absent"));
                };
                let want_dir = entry.op == WireOp::DirRename;
                if source.kind.is_dir() != want_dir {
                    return Err(invalid("rename kind differs from the current entry"));
                }
                if let Some(ino) = entry.ino {
                    if ino != source.ino {
                        return Err(invalid("rename inode differs from the source"));
                    }
                }
                if !want_dir {
                    if entry.size != source.size {
                        return Err(invalid("rename size differs from the source"));
                    }
                    if let Some(root) = entry.file_root {
                        if root != source.file_root {
                            return Err(invalid("rename file_root differs from the source"));
                        }
                    }
                    if let (Some(expected), Some(actual)) =
                        (entry.content_hash, source.content_hash)
                    {
                        if expected != actual {
                            return Err(invalid("rename content_hash differs from the source"));
                        }
                    }
                }
                if entry.op == WireOp::DirRename {
                    let source_path = child_path(dir_path, from);
                    let target_path = child_path(dir_path, &entry.name);
                    if let Some(lock) = locks.iter().find(|lock| {
                        path_is_within(&lock.dir_path, &source_path)
                            || path_is_within(&lock.dir_path, &target_path)
                    }) {
                        return Err(Fault::lock_held(lock));
                    }
                }
                if existing.is_some() && !renamed_away.contains(entry.name.as_str()) {
                    return Err(Fault::name_conflict("rename target is not empty"));
                }
            }
            WireOp::Keep => {
                let Some(record) = existing else {
                    return Err(invalid("KEEP names an absent entry"));
                };
                if kind(entry.kind) != record.kind {
                    return Err(invalid("KEEP kind differs from the current entry"));
                }
                if let Some(ino) = entry.ino {
                    if ino != record.ino {
                        return Err(invalid("KEEP inode differs from the current entry"));
                    }
                }
                if let Some(root) = entry.file_root {
                    if root != record.file_root {
                        return Err(invalid("KEEP file_root differs; use PUT"));
                    }
                }
                if entry.size != record.size && !record.kind.is_dir() {
                    return Err(invalid("KEEP size differs; use PUT"));
                }
                if let (Some(expected), Some(actual)) = (entry.content_hash, record.content_hash) {
                    if expected != actual {
                        return Err(invalid("KEEP content_hash differs; use PUT"));
                    }
                }
            }
            WireOp::Put => {
                if kind(entry.kind).is_dir() {
                    return Err(invalid("PUT carries a directory kind"));
                }
                if let Some(record) = existing {
                    if record.kind.is_dir() {
                        check_replace_dir(record, locks, dir_path)?;
                    }
                }
            }
            WireOp::DirAdd => {
                if let Some(record) = existing {
                    if record.kind.is_dir() {
                        return Err(invalid("DIR_ADD names an existing directory"));
                    }
                }
            }
        }
    }
    Ok(())
}

fn check_replace_dir(
    record: &FileRecord,
    locks: &[LockRecord],
    dir_path: &str,
) -> Result<(), Fault> {
    let path = child_path(dir_path, &record.name);
    if let Some(lock) = locks
        .iter()
        .find(|lock| path_is_within(&lock.dir_path, &path))
    {
        return Err(Fault::lock_held(lock));
    }
    Ok(())
}

fn invalid(detail: &'static str) -> Fault {
    Fault::detail(ErrorCode::ManifestInvalid, detail)
}

/// Build the final manifest: every non-removed entry with `KEEP`.
pub fn desired_manifest(entries: &[ManifestEntry]) -> Result<Manifest, Fault> {
    let desired: Vec<ManifestEntry> = entries
        .iter()
        .filter(|entry| !entry.op.is_delete())
        .map(|entry| {
            let mut entry = entry.clone();
            entry.op = EntryOp::Keep;
            entry.from_name = None;
            entry
        })
        .collect();
    Manifest::new(desired).map_err(manifest_fault)
}

fn manifest_fault(error: ManifestError) -> Fault {
    Fault::detail(ErrorCode::ManifestInvalid, error.to_string())
}

/// Derive the plan shown in `UPLOAD_PLAN`.
pub fn plan(
    base: &[ManifestEntry],
    entries: &[ManifestEntry],
    mode: UploadMode,
) -> Result<Vec<PlanItem>, Fault> {
    let base_manifest = Manifest::from_base_entries(base.to_vec()).map_err(manifest_fault)?;
    let desired = desired_manifest(entries)?;
    let diff =
        Manifest::diff(base_manifest.entries(), desired.entries()).map_err(manifest_fault)?;
    let base_inos: HashSet<Ino> = base.iter().map(|entry| entry.ino).collect();
    let mut items = Vec::with_capacity(diff.len());
    for entry in diff.entries() {
        let action = match entry.op {
            EntryOp::Keep => PlanAction::Keep,
            EntryOp::Put => {
                if mode == UploadMode::Full {
                    PlanAction::PutFull
                } else if base_inos.contains(&entry.ino) {
                    PlanAction::PutDelta
                } else {
                    PlanAction::PutFull
                }
            }
            EntryOp::Delete => PlanAction::Delete,
            EntryOp::Rename => PlanAction::Rename,
            EntryOp::DirAdd => PlanAction::DirAdd,
            EntryOp::DirRemove => PlanAction::DirRemove,
            EntryOp::DirRename => PlanAction::DirRename,
        };
        let reason = match action {
            PlanAction::Keep => None,
            PlanAction::PutDelta | PlanAction::PutFull => Some("content changed".to_owned()),
            PlanAction::Delete => Some("explicit delete".to_owned()),
            PlanAction::Rename => Some("rename".to_owned()),
            PlanAction::DirAdd => Some("new directory".to_owned()),
            PlanAction::DirRemove => Some("empty directory removed".to_owned()),
            PlanAction::DirRename => Some("directory renamed".to_owned()),
        };
        items.push(PlanItem {
            action,
            name: entry.name.clone(),
            reason,
        });
    }
    Ok(items)
}

fn feed_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u32).to_le_bytes());
    hasher.update(bytes);
}

// Keep the import used when a future field needs it; `DirSeq` is part of the
// public base contract but not used by this module.
const _: fn() = || {
    let _ = std::mem::size_of::<DirSeq>();
};

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::mmap::proto::{DirAttrs, Entry, EntryKind as WireKind, EntryOp as WireOp};
    use crate::mmap::types::{DirAttrs as TypedAttrs, ROOT_MODE};

    fn wire_file(name: &str, ino: [u8; 16], content: &[u8]) -> Entry {
        let chunks = chunks(content);
        Entry {
            name: name.to_owned(),
            ino: Some(ino),
            kind: WireKind::File,
            op: WireOp::Put,
            from_name: None,
            mode: 0o644,
            uid: 1,
            gid: 2,
            mtime_ns: 3,
            size: content.len() as u64,
            file_root: Some(base::file_root(EntryKind::File, None, &chunks)),
            content_hash: Some(*blake3::hash(content).as_bytes()),
            target: None,
        }
    }

    fn chunks(content: &[u8]) -> Vec<crate::store::sqlite::ChunkRef> {
        content
            .chunks(65_536)
            .enumerate()
            .map(|(index, bytes)| crate::store::sqlite::ChunkRef {
                chunk_no: index as u32,
                hash: *blake3::hash(bytes).as_bytes(),
                offset: index as u64 * 65_536,
                len: bytes.len() as u32,
            })
            .collect()
    }

    fn typed(entry: &Entry) -> ManifestEntry {
        ManifestEntry {
            name: entry.name.clone(),
            ino: entry.ino.unwrap(),
            kind: kind(entry.kind),
            op: op(entry.op),
            from_name: entry.from_name.clone(),
            mode: entry.mode,
            uid: entry.uid,
            gid: entry.gid,
            mtime_ns: entry.mtime_ns as i64,
            size: entry.size,
            file_root: entry.file_root.unwrap(),
            content_hash: entry.content_hash,
            target: entry.target.clone(),
        }
    }

    #[test]
    fn hash_matches_the_foundation_manifest() {
        let wire = vec![
            wire_file("a", [1; 16], b"hello"),
            wire_file("b", [2; 16], b""),
        ];
        let typed: Vec<ManifestEntry> = wire.iter().map(typed).collect();
        let manifest = Manifest::new(typed.clone()).unwrap();
        assert_eq!(manifest_hash(&typed), manifest.hash());
        assert_eq!(wire_manifest_hash(&wire).unwrap(), manifest.hash());
    }

    #[test]
    fn missing_inode_encodes_as_zero_in_the_wire_hash() {
        let mut wire = wire_file("a", [1; 16], b"x");
        wire.ino = None;
        let typed = wire_entry_for_hash(&wire).unwrap();
        assert_eq!(typed.ino, [0u8; 16]);
    }

    #[test]
    fn assigned_entries_are_sorted_and_get_a_nonzero_inode() {
        let wire = vec![wire_file("b", [2; 16], b"b"), wire_file("a", [1; 16], b"a")];
        let assigned = assign_entries(&wire, &[]).unwrap();
        assert_eq!(assigned[0].name, "a");
        assert_eq!(assigned[1].name, "b");

        let mut missing = wire_file("c", [0; 16], b"c");
        missing.ino = None;
        let assigned = assign_entries(&[missing], &[]).unwrap();
        assert_ne!(assigned[0].ino, ROOT_INO);
    }

    #[test]
    fn completeness_reports_a_missing_entry() {
        let current = FileRecord {
            ino: [1; 16],
            dir_ino: ROOT_INO,
            name: "old".to_owned(),
            kind: EntryKind::File,
            attrs: TypedAttrs {
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime_ns: 0,
            },
            size: 0,
            file_root: base::empty_file_root(),
            content_hash: Some(*blake3::hash(b"").as_bytes()),
            target: None,
            version: 1,
            deleted: false,
            created_at_ms: 0,
            updated_at_ms: 0,
        };
        let error = validate_entries(&[current], &[], &[], "/").unwrap_err();
        assert_eq!(error.body.code, ErrorCode::ManifestIncomplete);
        assert_eq!(error.body.missing, vec!["old".to_owned()]);
    }

    #[test]
    fn rename_must_not_land_on_a_live_name() {
        let attrs = TypedAttrs {
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime_ns: 0,
        };
        let record = |name: &str, ino: [u8; 16]| FileRecord {
            ino,
            dir_ino: ROOT_INO,
            name: name.to_owned(),
            kind: EntryKind::File,
            attrs,
            size: 0,
            file_root: base::empty_file_root(),
            content_hash: Some(*blake3::hash(b"").as_bytes()),
            target: None,
            version: 1,
            deleted: false,
            created_at_ms: 0,
            updated_at_ms: 0,
        };
        let current = vec![record("a", [1; 16]), record("b", [2; 16])];
        let mut wire = wire_file("b", [1; 16], b"");
        wire.op = WireOp::Rename;
        wire.from_name = Some("a".to_owned());
        let error = validate_entries(&current, &[wire], &[], "/").unwrap_err();
        assert_eq!(error.body.code, ErrorCode::NameConflict);
    }

    #[test]
    fn plan_uses_the_foundation_diff() {
        let wire = vec![wire_file("a", [1; 16], b"x")];
        let assigned = assign_entries(&wire, &[]).unwrap();
        let plan = plan(&[], &assigned, UploadMode::Full).unwrap();
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].action, PlanAction::PutFull);
        let _ = DirAttrs {
            mode: ROOT_MODE,
            uid: 0,
            gid: 0,
            mtime_ns: 0,
        };
    }
}
