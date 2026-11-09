//! Directory checkout and atomic publication.
//!
//! A checkout is one server snapshot transformed into local rows and files.
//! Bodies are written and verified in `staging/`; only after every body
//! matches its `file_root` and `content_hash` does the metadata transaction
//! publish the directory. A crash before that transaction leaves only orphan
//! staging files, which the next start removes.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use rusqlite::OptionalExtension;

use crate::mmap::base;
use crate::mmap::db::MmTx;
use crate::mmap::types::{
    BatchId, DirAttrs, DirRecord, DirSeq, EntryKind, FileRecord, Ino, ManifestEntry, MmBase, Phase,
    VersionRecord,
};

use super::content::{self, ContentHashes};
use super::db::{ShadowVersion, VersionState, allocate_fuse, put_shadow_version_tx};
use super::{Shadow, ShadowError, child_path, now_ms};

/// How one snapshot entry relates to the local tree.
#[derive(Clone, Debug)]
enum EntryAction {
    /// Local dirty content wins; only the base snapshot changes.
    Preserve { local: FileRecord },
    /// Same content; update attributes and possibly materialize a body.
    Same {
        local: FileRecord,
        body: Option<ContentHashes>,
    },
    /// A new content version is required.
    Replace {
        local: Option<FileRecord>,
        version: u64,
        body: Option<ContentHashes>,
    },
}

impl Shadow {
    /// Make one directory's direct entries available, optionally with bodies.
    ///
    /// `lookup` and `readdir` pass `bodies = false`; `open` and `create` pass
    /// `bodies = true` the first time. A fresh local-only directory never
    /// contacts the server.
    pub fn ensure_dir(&self, dir_ino: Ino, bodies: bool) -> Result<(), ShadowError> {
        let dir = self.db.shadow_dir(dir_ino)?.ok_or(ShadowError::NotFound)?;
        if dir.record.deleted {
            return Err(ShadowError::NotFound);
        }
        let now = now_ms();
        let fresh = dir.record.phase == Phase::Ready && dir.valid_until_ms > now;
        let bodies_ok = !bodies || dir.bodies_checked_out || dir.local_only;
        if fresh && bodies_ok {
            return Ok(());
        }
        if dir.local_only {
            return Ok(());
        }

        let slot = self.slot(dir_ino);
        let mut state = super::lock(&slot.state);
        loop {
            match *state {
                super::SlotState::Idle => {
                    *state = super::SlotState::CheckingOut;
                    break;
                }
                super::SlotState::CheckingOut => {
                    state = slot
                        .changed
                        .wait(state)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    // The leader either published a snapshot or failed.
                    match *state {
                        super::SlotState::Ready => return Ok(()),
                        super::SlotState::Failed { .. } => return Err(ShadowError::Stale),
                        _ => continue,
                    }
                }
                super::SlotState::Ready => {
                    // The fast path rejected the previous checkout (TTL or
                    // bodies), so this thread leads the next one.
                    *state = super::SlotState::CheckingOut;
                    break;
                }
                super::SlotState::Failed { retry_at } => {
                    if retry_at.is_some_and(|at| Instant::now() < at) {
                        return Err(ShadowError::Stale);
                    }
                    *state = super::SlotState::CheckingOut;
                    break;
                }
            }
        }
        drop(state);

        let result = self.checkout_once(dir_ino, bodies);
        let mut state = super::lock(&slot.state);
        *state = match &result {
            Ok(()) => super::SlotState::Ready,
            Err(_) => super::SlotState::Failed {
                retry_at: Some(Instant::now() + Duration::from_secs(1)),
            },
        };
        slot.changed.notify_all();
        result
    }

    /// Force a manifest revalidation on the next access.
    pub fn mark_stale(&self, dir_ino: Ino) -> Result<(), ShadowError> {
        self.db.write(|tx| {
            tx.conn().execute(
                "UPDATE mm_dirs SET phase = 'stale' WHERE namespace = ?1 AND ino = ?2",
                rusqlite::params![self.namespace, dir_ino.as_slice()],
            )?;
            tx.conn().execute(
                "UPDATE shadow_dirs SET valid_until_ms = 0 WHERE dir_ino = ?1",
                rusqlite::params![dir_ino.as_slice()],
            )?;
            Ok(())
        })
    }

    fn checkout_once(&self, dir_ino: Ino, bodies: bool) -> Result<(), ShadowError> {
        let dir = self.db.shadow_dir(dir_ino)?.ok_or(ShadowError::NotFound)?;
        let if_base = if (bodies && !dir.bodies_checked_out) || dir.record.base.dir_seq.get() == 0 {
            None
        } else {
            Some(dir.record.base)
        };
        let request = super::remote::CheckoutRequest {
            dir_path: dir.record.path.clone(),
            dir_ino,
            if_base,
            if_snapshot: if_base.map(|_| dir.snapshot_seq),
            bodies,
        };
        let first = self.remote.checkout(&request);
        let outcome = match first {
            Ok(outcome) => outcome,
            Err(super::RemoteError::BaseChanged { .. }) if if_base.is_some() => {
                // The cached base is stale. A directory refresh may take a
                // full snapshot; an upload revalidation must *not* do this
                // and returns the conflict to fsync instead.
                self.remote.checkout(&super::remote::CheckoutRequest {
                    if_base: None,
                    if_snapshot: None,
                    ..request
                })?
            }
            Err(error) => return Err(error.into()),
        };
        match outcome {
            super::remote::CheckoutOutcome::NotModified { base, snapshot_seq } => {
                let valid_until = now_ms()
                    .saturating_add(i64::try_from(self.ttl.as_millis()).unwrap_or(i64::MAX));
                self.db.set_checkout_state(
                    dir_ino,
                    &base,
                    snapshot_seq,
                    &dir.record.attrs,
                    Phase::Ready,
                    bodies,
                    valid_until,
                )?;
                Ok(())
            }
            super::remote::CheckoutOutcome::Snapshot(snapshot) => {
                self.apply_snapshot(snapshot, bodies)
            }
        }
    }

    /// Apply one complete server snapshot to the local tree.
    ///
    /// Every body is verified before publication. Local dirty versions are
    /// preserved; clean versions follow the server. Deletions become explicit
    /// tombstones only for entries that are not locally dirty.
    pub(super) fn apply_snapshot(
        &self,
        snapshot: super::remote::CheckoutSnapshot,
        bodies: bool,
    ) -> Result<(), ShadowError> {
        let dir_ino = snapshot.dir_ino;
        let dir = self.db.shadow_dir(dir_ino)?.ok_or(ShadowError::NotFound)?;
        let parent_path = dir.record.path.clone();
        let local_live: Vec<FileRecord> = self.db.files(dir_ino)?;
        let local_by_ino: BTreeMap<Ino, FileRecord> = local_live
            .iter()
            .map(|file| (file.ino, file.clone()))
            .collect();
        let local_by_name: BTreeMap<String, FileRecord> = local_live
            .into_iter()
            .map(|file| (file.name.clone(), file))
            .collect();

        let mut body_by_ino: HashMap<Ino, Vec<u8>> = HashMap::new();
        for body in snapshot.bodies {
            body_by_ino.insert(body.ino, body.bytes);
        }

        // Verify all bodies and stage them before any metadata changes.
        let checkout_id = BatchId::new_random();
        let staging = self.layout.create_staging(&dir_ino, checkout_id)?;
        let mut staged: HashMap<Ino, std::path::PathBuf> = HashMap::new();
        for entry in &snapshot.entries {
            if entry.kind != EntryKind::File {
                continue;
            }
            let Some(bytes) = body_by_ino.get(&entry.ino) else {
                continue;
            };
            let hashes = content::verify_bytes(
                bytes,
                entry.size,
                &entry.file_root,
                entry.content_hash.as_ref(),
            )?;
            let path = staging.join(format!("{}.body", super::hex16(&entry.ino)));
            content::write_staged(&path, bytes).map_err(|error| {
                let _ = std::fs::remove_dir_all(&staging);
                ShadowError::Io(error)
            })?;
            if hashes.size != entry.size {
                let _ = std::fs::remove_dir_all(&staging);
                return Err(ShadowError::Invalid("staged body size changed"));
            }
            staged.insert(entry.ino, path);
        }

        let mut actions: Vec<(super::remote::CheckoutEntry, EntryAction)> = Vec::new();
        let mut server_inos = std::collections::HashSet::new();
        for entry in &snapshot.entries {
            server_inos.insert(entry.ino);
            let local = local_by_ino.get(&entry.ino).cloned();
            let action = self.classify_entry(entry, local.as_ref(), staged.get(&entry.ino))?;
            actions.push((entry.clone(), action));
        }

        // Publish object files and directory links before the database
        // transaction. A crash here leaves unreferenced objects; the next
        // start removes them.
        for (entry, action) in &actions {
            match action {
                EntryAction::Preserve { local } => {
                    self.relink_renamed(entry, Some(local))?;
                    self.link_if_present(entry, local.version, &parent_path)?;
                }
                EntryAction::Same { local, body } => {
                    if let Some(hashes) = body {
                        if !self.layout.object_path(&entry.ino, local.version).exists() {
                            if let Some(path) = staged.get(&entry.ino) {
                                content::publish_staged(
                                    &self.layout,
                                    &entry.ino,
                                    local.version,
                                    path,
                                )
                                .map_err(|error| {
                                    let _ = std::fs::remove_dir_all(&staging);
                                    ShadowError::Io(error)
                                })?;
                            }
                        }
                        // `hashes` is equal to the verified entry root.
                        debug_assert_eq!(hashes.file_root, entry.file_root);
                    }
                    self.relink_renamed(entry, Some(local))?;
                    self.link_if_present(entry, local.version, &parent_path)?;
                }
                EntryAction::Replace {
                    local,
                    version,
                    body: _,
                } => {
                    if let Some(path) = staged.get(&entry.ino) {
                        if self.layout.object_path(&entry.ino, *version).exists() {
                            let _ = self.layout.remove_object(&entry.ino, *version);
                        }
                        content::publish_staged(&self.layout, &entry.ino, *version, path).map_err(
                            |error| {
                                let _ = std::fs::remove_dir_all(&staging);
                                ShadowError::Io(error)
                            },
                        )?;
                    } else if entry.kind == EntryKind::File {
                        // No body: expose no stale bytes. `open` will request a
                        // full checkout the next time bodies are needed.
                        let _ = self.layout.unlink_entry(&dir_ino, &entry.name);
                    }
                    if entry.kind == EntryKind::File && staged.contains_key(&entry.ino) {
                        self.layout
                            .link_entry(&dir_ino, &entry.name, &entry.ino, *version)
                            .map_err(ShadowError::Io)?;
                    }
                    self.relink_renamed(entry, local.as_ref())?;
                    if let Some(local) = local {
                        if local.version != *version {
                            let _ = self.layout.object_path(&entry.ino, local.version);
                        }
                    }
                }
            }
        }

        // Removed clean entries must disappear from the shadow directory too.
        // A locally created child directory has no `shadow_versions` row: its
        // structure commits with this directory's batch, and only then does
        // `publish_committed` clear `local_only`. Its version is always 0, so
        // the dirty-version test alone would classify it as clean and tombstone
        // the directory before the manifest is built.
        let mut removed = Vec::new();
        for (name, local) in &local_by_name {
            if server_inos.contains(&local.ino) {
                continue;
            }
            let is_dirty = if local.kind == EntryKind::Dir {
                self.db
                    .shadow_dir(local.ino)?
                    .is_some_and(|dir| dir.local_only)
            } else {
                self.db
                    .shadow_version(local.ino, local.version)?
                    .is_some_and(|version| {
                        version.dirty_gen > 0
                            || matches!(
                                version.state,
                                VersionState::Dirty | VersionState::Uploading
                            )
                    })
            };
            if !is_dirty {
                let _ = self.layout.unlink_entry(&dir_ino, name);
                removed.push((name.clone(), local.clone()));
            }
        }

        let valid_until =
            now_ms().saturating_add(i64::try_from(self.ttl.as_millis()).unwrap_or(i64::MAX));
        let result = self.db.write(|tx| {
            // Child directory rows and direct entries.
            for (entry, action) in &actions {
                if entry.kind == EntryKind::Dir {
                    self.upsert_child_dir_tx(tx, &parent_path, entry, snapshot.base)?;
                    let record = FileRecord {
                        ino: entry.ino,
                        dir_ino,
                        name: entry.name.clone(),
                        kind: EntryKind::Dir,
                        attrs: entry.attrs,
                        size: 0,
                        file_root: base::dir_root(),
                        content_hash: None,
                        target: None,
                        version: 0,
                        deleted: false,
                        created_at_ms: now_ms(),
                        updated_at_ms: now_ms(),
                    };
                    tx.put_file(&record)?;
                    allocate_fuse(tx.conn(), entry.ino, 0, EntryKind::Dir)?;
                    continue;
                }

                match action {
                    EntryAction::Preserve { local } => {
                        // A dirty local version keeps its name and attributes.
                        // The base snapshot still records the server entry.
                        if local.name != entry.name {
                            let mut moved = local.clone();
                            moved.name = entry.name.clone();
                            moved.updated_at_ms = now_ms();
                            tx.put_file(&moved)?;
                        }
                    }
                    EntryAction::Same { local, body } => {
                        let hashes = body.unwrap_or(ContentHashes {
                            size: entry.size,
                            file_root: entry.file_root,
                            content_hash: entry.content_hash.unwrap_or([0u8; 32]),
                        });
                        let hashes = ContentHashes {
                            content_hash: body
                                .map_or(hashes.content_hash, |hashes| hashes.content_hash),
                            ..hashes
                        };
                        let version = local.version;
                        let record = FileRecord {
                            ino: entry.ino,
                            dir_ino,
                            name: entry.name.clone(),
                            kind: entry.kind,
                            attrs: entry.attrs,
                            size: hashes.size,
                            file_root: hashes.file_root,
                            content_hash: (entry.kind == EntryKind::File)
                                .then_some(hashes.content_hash),
                            target: entry.target.clone(),
                            version,
                            deleted: false,
                            created_at_ms: local.created_at_ms,
                            updated_at_ms: now_ms(),
                        };
                        tx.put_file(&record)?;
                        let has_body = body.is_some()
                            || self
                                .layout
                                .object_path(&record.ino, version)
                                .exists();
                        write_version_tx(tx, &record, has_body)?;
                    }
                    EntryAction::Replace {
                        local,
                        version,
                        body,
                    } => {
                        let hashes = body.unwrap_or(ContentHashes {
                            size: entry.size,
                            file_root: entry.file_root,
                            content_hash: entry.content_hash.unwrap_or([0u8; 32]),
                        });
                        let hashes = ContentHashes {
                            content_hash: body
                                .map_or(hashes.content_hash, |hashes| hashes.content_hash),
                            ..hashes
                        };
                        let record = FileRecord {
                            ino: entry.ino,
                            dir_ino,
                            name: entry.name.clone(),
                            kind: entry.kind,
                            attrs: entry.attrs,
                            size: hashes.size,
                            file_root: hashes.file_root,
                            content_hash: (entry.kind == EntryKind::File)
                                .then_some(hashes.content_hash),
                            target: entry.target.clone(),
                            version: *version,
                            deleted: false,
                            created_at_ms: local.as_ref().map_or_else(now_ms, |f| f.created_at_ms),
                            updated_at_ms: now_ms(),
                        };
                        tx.put_file(&record)?;
                        write_version_tx(
                            tx,
                            &record,
                            body.is_some() || entry.kind != EntryKind::File,
                        )?;
                        allocate_fuse(tx.conn(), entry.ino, *version, entry.kind)?;
                    }
                }
            }

            // Clean local entries the server no longer lists become explicit
            // tombstones. Dirty entries survive and are re-uploaded. The
            // dirty flags are read before the write transaction starts; a
            // nested read on the same handle would deadlock.
            for (_name, local) in &removed {
                let mut tombstone = local.clone();
                tombstone.deleted = true;
                tombstone.updated_at_ms = now_ms();
                tx.put_file(&tombstone)?;
                tx.conn().execute(
                    "UPDATE shadow_versions SET state = 'deleted'
                     WHERE ino = ?1 AND version = ?2 AND dirty_gen = 0",
                    rusqlite::params![
                        local.ino.as_slice(),
                        i64::try_from(local.version)
                            .map_err(|_| ShadowError::Invalid("version does not fit i64"))?
                    ],
                )?;
            }

            // The server base is the authoritative snapshot, independent of
            // local dirty overlay entries.
            tx.conn().execute(
                "DELETE FROM mm_base WHERE namespace = ?1 AND dir_ino = ?2",
                rusqlite::params![self.namespace, dir_ino.as_slice()],
            )?;
            for entry in &snapshot.entries {
                let base_entry = entry.manifest_entry(crate::mmap::types::EntryOp::Keep);
                insert_base_tx(tx, &self.namespace, dir_ino, &base_entry)?;
            }

            // Publish the new directory state.
            tx.conn().execute(
                "UPDATE mm_dirs
                 SET base_epoch = ?1, base_seq = ?2, dir_version = ?3, phase = 'ready',
                     mode = ?4, uid = ?5, gid = ?6, mtime_ns = ?7, deleted = 0,
                     updated_at_ms = ?8
                 WHERE namespace = ?9 AND ino = ?10",
                rusqlite::params![
                    i64::try_from(snapshot.base.epoch)
                        .map_err(|_| ShadowError::Invalid("epoch does not fit i64"))?,
                    i64::try_from(snapshot.base.dir_seq.get())
                        .map_err(|_| ShadowError::Invalid("dir_seq does not fit i64"))?,
                    snapshot.base.dir_version.as_slice(),
                    i64::from(snapshot.attrs.mode),
                    i64::from(snapshot.attrs.uid),
                    i64::from(snapshot.attrs.gid),
                    snapshot.attrs.mtime_ns,
                    now_ms(),
                    self.namespace,
                    dir_ino.as_slice(),
                ],
            )?;
            tx.conn().execute(
                "INSERT INTO shadow_dirs
                   (dir_ino, valid_until_ms, dirty_gen, uploaded_gen, upload_state,
                    batch_id, lock_id, dir_handles, bodies_checked_out, local_only,
                    snapshot_seq, last_checkout_ms)
                 VALUES (?1, ?2, 0, 0, 'idle', NULL, NULL, 0, ?3, 0, ?4, ?5)
                 ON CONFLICT(dir_ino) DO UPDATE SET
                   valid_until_ms = excluded.valid_until_ms,
                   bodies_checked_out = MAX(shadow_dirs.bodies_checked_out, excluded.bodies_checked_out),
                   snapshot_seq = excluded.snapshot_seq,
                   last_checkout_ms = excluded.last_checkout_ms",
                rusqlite::params![
                    dir_ino.as_slice(),
                    valid_until,
                    i64::from(bodies),
                    i64::try_from(snapshot.snapshot_seq.get())
                        .map_err(|_| ShadowError::Invalid("snapshot seq does not fit i64"))?,
                    now_ms(),
                ],
            )?;
            tx.conn().execute(
                "INSERT INTO mm_dir_versions
                   (namespace, dir_ino, dir_path, base_epoch, dir_seq, snapshot_seq,
                    dir_version, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(namespace, dir_ino) DO UPDATE SET
                   dir_path = excluded.dir_path,
                   base_epoch = excluded.base_epoch,
                   dir_seq = excluded.dir_seq,
                   snapshot_seq = excluded.snapshot_seq,
                   dir_version = excluded.dir_version,
                   updated_at_ms = excluded.updated_at_ms",
                rusqlite::params![
                    self.namespace,
                    dir_ino.as_slice(),
                    parent_path,
                    i64::try_from(snapshot.base.epoch)
                        .map_err(|_| ShadowError::Invalid("epoch does not fit i64"))?,
                    i64::try_from(snapshot.base.dir_seq.get())
                        .map_err(|_| ShadowError::Invalid("dir_seq does not fit i64"))?,
                    i64::try_from(snapshot.snapshot_seq.get())
                        .map_err(|_| ShadowError::Invalid("snapshot seq does not fit i64"))?,
                    snapshot.base.dir_version.as_slice(),
                    now_ms(),
                ],
            )?;
            Ok(())
        });
        let _ = std::fs::remove_dir_all(&staging);
        result
    }

    fn classify_entry(
        &self,
        entry: &super::remote::CheckoutEntry,
        local: Option<&FileRecord>,
        staged: Option<&std::path::PathBuf>,
    ) -> Result<EntryAction, ShadowError> {
        let body_present = staged.is_some();
        let Some(local) = local else {
            let version = 1;
            let body = self.body_hashes(entry, staged)?;
            return Ok(EntryAction::Replace {
                local: None,
                version,
                body,
            });
        };
        let local_version = self.db.shadow_version(local.ino, local.version)?;
        let dirty = local_version.as_ref().is_some_and(|version| {
            version.dirty_gen > 0
                || matches!(version.state, VersionState::Dirty | VersionState::Uploading)
        });
        if dirty {
            return Ok(EntryAction::Preserve {
                local: local.clone(),
            });
        }
        let same = local.kind == entry.kind
            && local.file_root == entry.file_root
            && local.size == entry.size
            && local.target == entry.target;
        if same {
            let body = if body_present {
                self.body_hashes(entry, staged)?
            } else {
                None
            };
            return Ok(EntryAction::Same {
                local: local.clone(),
                body,
            });
        }
        let version = local.version.saturating_add(1);
        let body = self.body_hashes(entry, staged)?;
        Ok(EntryAction::Replace {
            local: Some(local.clone()),
            version,
            body,
        })
    }

    fn body_hashes(
        &self,
        entry: &super::remote::CheckoutEntry,
        staged: Option<&std::path::PathBuf>,
    ) -> Result<Option<ContentHashes>, ShadowError> {
        let Some(path) = staged else {
            return Ok(None);
        };
        let hashes = content::hash_file(path)?;
        if hashes.file_root != entry.file_root || hashes.size != entry.size {
            return Err(ShadowError::Invalid("staged body does not match the entry"));
        }
        if entry.kind == EntryKind::File {
            if let Some(expected) = entry.content_hash {
                if hashes.content_hash != expected {
                    return Err(ShadowError::Invalid("staged content hash does not match"));
                }
            }
        }
        Ok(Some(hashes))
    }

    fn link_if_present(
        &self,
        entry: &super::remote::CheckoutEntry,
        version: u64,
        parent: &str,
    ) -> Result<(), ShadowError> {
        if entry.kind != EntryKind::File {
            return Ok(());
        }
        if self.layout.object_path(&entry.ino, version).exists() {
            self.layout
                .link_entry(&self.dir_ino_of(parent)?, &entry.name, &entry.ino, version)?;
        }
        Ok(())
    }

    /// Remove an old directory link when the server renamed the same inode.
    fn relink_renamed(
        &self,
        entry: &super::remote::CheckoutEntry,
        local: Option<&FileRecord>,
    ) -> Result<(), ShadowError> {
        let Some(local) = local else {
            return Ok(());
        };
        if local.name == entry.name {
            return Ok(());
        }
        let _ = self.layout.unlink_entry(&local.dir_ino, &local.name);
        Ok(())
    }

    fn dir_ino_of(&self, path: &str) -> Result<Ino, ShadowError> {
        self.db
            .shadow_dir_by_path(path)?
            .map(|dir| dir.record.ino)
            .ok_or(ShadowError::NotFound)
    }

    fn upsert_child_dir_tx(
        &self,
        tx: &crate::mmap::WriteTx<'_>,
        parent_path: &str,
        entry: &super::remote::CheckoutEntry,
        base: MmBase,
    ) -> Result<(), ShadowError> {
        let path = child_path(parent_path, &entry.name);
        let existing = tx.dir(entry.ino)?;
        let dir_version = base::dir_version(&self.namespace, entry.ino, &entry.attrs, &[]);
        let local_only: bool = tx
            .conn()
            .query_row(
                "SELECT local_only FROM shadow_dirs WHERE dir_ino = ?1",
                rusqlite::params![entry.ino.as_slice()],
                |row| Ok(row.get::<_, i64>(0)? != 0),
            )
            .optional()?
            .unwrap_or(false);
        let base = if existing.is_some() && !local_only {
            existing.as_ref().map_or(
                MmBase::new(base.epoch, DirSeq::ZERO, dir_version),
                |record| record.base,
            )
        } else {
            MmBase::new(base.epoch, DirSeq::ZERO, dir_version)
        };
        let record = DirRecord {
            ino: entry.ino,
            path,
            base,
            phase: if local_only {
                Phase::Stale
            } else {
                existing
                    .as_ref()
                    .map_or(Phase::Absent, |record| record.phase)
            },
            attrs: entry.attrs,
            deleted: false,
            created_at_ms: existing
                .as_ref()
                .map_or_else(now_ms, |record| record.created_at_ms),
            updated_at_ms: now_ms(),
        };
        tx.put_dir(&record)?;
        tx.conn().execute(
            "INSERT INTO shadow_dirs (dir_ino, upload_state, local_only, bodies_checked_out)
             VALUES (?1, 'idle', 0, 0)
             ON CONFLICT(dir_ino) DO UPDATE SET
               valid_until_ms = CASE WHEN shadow_dirs.local_only = 1 THEN 0 ELSE shadow_dirs.valid_until_ms END,
               bodies_checked_out = CASE WHEN shadow_dirs.local_only = 1 THEN 0 ELSE shadow_dirs.bodies_checked_out END,
               local_only = 0",
            rusqlite::params![entry.ino.as_slice()],
        )?;
        allocate_fuse(tx.conn(), entry.ino, 0, EntryKind::Dir)?;
        Ok(())
    }
}

fn write_version_tx(
    tx: &crate::mmap::WriteTx<'_>,
    record: &FileRecord,
    has_body: bool,
) -> Result<(), ShadowError> {
    let content_hash = record
        .content_hash
        .unwrap_or_else(|| *blake3::hash(record.target.as_deref().unwrap_or_default()).as_bytes());
    let version_record = VersionRecord {
        ino: record.ino,
        version: record.version,
        size: record.size,
        file_root: record.file_root,
        content_hash,
        chunk_count: if record.kind == EntryKind::File {
            u32::try_from(record.size.div_ceil(65_536)).unwrap_or(u32::MAX)
        } else {
            0
        },
        created_at_ms: now_ms(),
    };
    tx.put_version(&version_record)?;
    let existing = tx
        .conn()
        .query_row(
            "SELECT open_refs, dirty_gen, state FROM shadow_versions
             WHERE ino = ?1 AND version = ?2",
            rusqlite::params![
                record.ino.as_slice(),
                i64::try_from(record.version)
                    .map_err(|_| ShadowError::Invalid("version does not fit i64"))?
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    let (open_refs, dirty_gen, existing_state) = existing
        .map(|(open_refs, dirty_gen, state)| {
            (
                u64::try_from(open_refs).unwrap_or(0),
                u64::try_from(dirty_gen).unwrap_or(0),
                VersionState::parse(&state),
            )
        })
        .unwrap_or((0, 0, None));
    let clean = record.kind != EntryKind::File
        || has_body
        || (existing_state == Some(VersionState::Clean) && dirty_gen == 0);
    let state = if clean {
        VersionState::Clean
    } else {
        VersionState::Remote
    };
    let local = ShadowVersion {
        ino: record.ino,
        version: record.version,
        size: record.size,
        file_root: record.file_root,
        content_hash,
        mtime_ns: record.attrs.mtime_ns,
        dirty_gen,
        synced_size: record.size,
        synced_mtime_ns: record.attrs.mtime_ns,
        open_refs,
        state,
    };
    put_shadow_version_tx(tx.conn(), &local)?;
    Ok(())
}

fn insert_base_tx(
    tx: &crate::mmap::WriteTx<'_>,
    namespace: &str,
    dir_ino: Ino,
    entry: &ManifestEntry,
) -> Result<(), ShadowError> {
    tx.conn().execute(
        "INSERT INTO mm_base
           (namespace, dir_ino, name, ino, kind, mode, uid, gid, mtime_ns,
            size, file_root, content_hash, target)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        rusqlite::params![
            namespace,
            dir_ino.as_slice(),
            entry.name,
            entry.ino.as_slice(),
            entry.kind.as_str(),
            i64::from(entry.mode),
            i64::from(entry.uid),
            i64::from(entry.gid),
            entry.mtime_ns,
            i64::try_from(entry.size).map_err(|_| ShadowError::Invalid("size does not fit i64"))?,
            entry.file_root.as_slice(),
            entry.content_hash.as_ref().map(|hash| hash.as_slice()),
            entry.target.as_deref(),
        ],
    )?;
    Ok(())
}

/// Root directory `DirRecord` for a freshly created local directory.
pub(super) fn local_dir_record(
    namespace: &str,
    ino: Ino,
    path: String,
    attrs: DirAttrs,
    epoch: u64,
) -> DirRecord {
    let version = base::dir_version(namespace, ino, &attrs, &[]);
    DirRecord {
        ino,
        path,
        base: MmBase::new(epoch.max(1), DirSeq::ZERO, version),
        phase: Phase::Ready,
        attrs,
        deleted: false,
        created_at_ms: now_ms(),
        updated_at_ms: now_ms(),
    }
}
