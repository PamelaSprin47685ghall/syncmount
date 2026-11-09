//! Unit and integration-level tests for the shadow filesystem.
//!
//! The mock remote below is the only server used here. It implements the same
//! `MmRemote` boundary P4 will implement over HTTP, so these tests exercise
//! the real checkout, manifest, rsync and commit assembly.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

use crate::mmap::base;
use crate::mmap::db::MmTx;
use crate::mmap::rsync::{Instruction, Signature, block_size_for, decode_from, sign};
use crate::mmap::types::{
    BatchId, DirAttrs, EntryKind, EntryOp, FileRecord, Hash, Ino, LockId, ManifestEntry, MmBase,
    MmSeq, ROOT_INO,
};

use super::remote::{
    BatchState, BatchStatus, CheckoutEntry, CheckoutOutcome, CheckoutRequest, CheckoutSnapshot,
    FileData, FileReadRequest, GrantedLock, LockRequest, LockResponse, MmRemote, RemoteError,
    SignatureFilePlan, SignaturesRequest, SignaturesResponse, UploadAbort, UploadBegin,
    UploadRequest, UploadResponse, UploadResult,
};
use super::{Shadow, ShadowConfig, ShadowDir, ShadowError, UploadPhase, VersionState};

const NS: &str = "/private-mm";

#[derive(Debug)]
struct MockDir {
    attrs: DirAttrs,
    entries: BTreeMap<String, ManifestEntry>,
    bodies: HashMap<Ino, Vec<u8>>,
    base: MmBase,
}

#[derive(Clone, Copy, Debug)]
enum FailPoint {
    Any,
    BatchStatus,
    Checkout,
    Lock,
    Upload,
}

/// Deterministic in-memory server.
struct MockRemote {
    state: Mutex<MockState>,
    fail: Mutex<Option<(FailPoint, RemoteError)>>,
    checkouts: AtomicUsize,
    statuses: AtomicUsize,
    /// Answer a stale `if_base` with a full snapshot instead of
    /// `BaseChanged`, as the wire server does.
    snapshot_when_stale: AtomicBool,
}

struct MockState {
    epoch: u64,
    snapshot_seq: u64,
    dirs: BTreeMap<Ino, MockDir>,
    commits: Vec<super::remote::UploadCommit>,
    batches: HashMap<BatchId, MockBatch>,
    locks: HashMap<Ino, LockId>,
}

#[derive(Clone, Debug)]
struct MockBatch {
    state: BatchState,
    manifest_hash: Hash,
    dir_path: String,
    /// Base, global sequence and directory version, when committed.
    result: Option<(MmBase, MmSeq, Hash)>,
}

impl MockRemote {
    fn new() -> Arc<Self> {
        let attrs = DirAttrs {
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime_ns: 1,
        };
        let version = base::dir_version(NS, ROOT_INO, &attrs, &[]);
        Arc::new(Self {
            state: Mutex::new(MockState {
                epoch: 1,
                snapshot_seq: 1,
                dirs: BTreeMap::from([(
                    ROOT_INO,
                    MockDir {
                        attrs,
                        entries: BTreeMap::new(),
                        bodies: HashMap::new(),
                        base: MmBase::new(1, crate::mmap::types::DirSeq::new(1), version),
                    },
                )]),
                commits: Vec::new(),
                batches: HashMap::new(),
                locks: HashMap::new(),
            }),
            fail: Mutex::new(None),
            checkouts: AtomicUsize::new(0),
            statuses: AtomicUsize::new(0),
            snapshot_when_stale: AtomicBool::new(false),
        })
    }

    fn set_snapshot_when_stale(&self, enabled: bool) {
        self.snapshot_when_stale.store(enabled, Ordering::Relaxed);
    }

    fn add_dir(&self, ino: Ino, parent: Ino, name: &str, attrs: DirAttrs) {
        let mut state = self.state.lock().unwrap();
        let mut parent_dir = state.dirs.remove(&parent).unwrap();
        let mut entry = entry_for_dir(name, ino, attrs);
        entry.op = EntryOp::Keep;
        parent_dir.entries.insert(name.to_owned(), entry);
        state.dirs.insert(parent, parent_dir);
        let version = base::dir_version(NS, ino, &attrs, &[]);
        state.dirs.insert(
            ino,
            MockDir {
                attrs,
                entries: BTreeMap::new(),
                bodies: HashMap::new(),
                base: MmBase::new(1, crate::mmap::types::DirSeq::new(1), version),
            },
        );
        recompute(&mut state, parent);
    }

    fn put_file(&self, dir: Ino, name: &str, ino: Ino, body: &[u8], mode: u32) {
        let mut state = self.state.lock().unwrap();
        let hashes = super::content::hash_bytes(body);
        let mut dir_state = state.dirs.remove(&dir).unwrap();
        dir_state.entries.insert(
            name.to_owned(),
            ManifestEntry {
                name: name.to_owned(),
                ino,
                kind: EntryKind::File,
                op: EntryOp::Keep,
                from_name: None,
                mode,
                uid: 1000,
                gid: 1000,
                mtime_ns: 10,
                size: hashes.size,
                file_root: hashes.file_root,
                content_hash: Some(hashes.content_hash),
                target: None,
            },
        );
        dir_state.bodies.insert(ino, body.to_vec());
        state.dirs.insert(dir, dir_state);
        recompute(&mut state, dir);
    }

    fn body(&self, dir: Ino, name: &str) -> Option<Vec<u8>> {
        let state = self.state.lock().unwrap();
        let dir = state.dirs.get(&dir)?;
        let entry = dir.entries.get(name)?;
        dir.bodies.get(&entry.ino).cloned()
    }

    /// Change one directory's attributes without touching its entries.
    fn touch_dir(&self, ino: Ino) {
        let mut state = self.state.lock().unwrap();
        {
            let dir = state.dirs.get_mut(&ino).unwrap();
            dir.attrs.mtime_ns = dir.attrs.mtime_ns.saturating_add(1);
        }
        recompute(&mut state, ino);
    }

    fn base(&self, dir: Ino) -> MmBase {
        self.state.lock().unwrap().dirs[&dir].base
    }

    fn commits(&self) -> Vec<super::remote::UploadCommit> {
        self.state.lock().unwrap().commits.clone()
    }

    fn batch_state(&self, batch_id: BatchId) -> Option<BatchState> {
        self.state
            .lock()
            .unwrap()
            .batches
            .get(&batch_id)
            .map(|batch| batch.state)
    }

    fn batch_count(&self) -> usize {
        self.state.lock().unwrap().batches.len()
    }

    fn dir_exists(&self, ino: Ino) -> bool {
        self.state.lock().unwrap().dirs.contains_key(&ino)
    }

    fn dir_entry_count(&self, ino: Ino) -> Option<usize> {
        self.state
            .lock()
            .unwrap()
            .dirs
            .get(&ino)
            .map(|dir| dir.entries.len())
    }

    fn statuses(&self) -> usize {
        self.statuses.load(Ordering::Relaxed)
    }

    fn snapshot_seq(&self) -> MmSeq {
        MmSeq::new(self.state.lock().unwrap().snapshot_seq)
    }

    fn set_failure(&self, point: FailPoint, error: RemoteError) {
        *self.fail.lock().unwrap() = Some((point, error));
    }

    fn clear_failure(&self) {
        *self.fail.lock().unwrap() = None;
    }

    fn fail_if(&self, point: FailPoint) -> Result<(), RemoteError> {
        let mut fail = self.fail.lock().unwrap();
        if let Some((at, error)) = fail.as_ref() {
            if matches!(at, FailPoint::Any)
                || std::mem::discriminant(at) == std::mem::discriminant(&point)
            {
                let error = error.clone();
                *fail = None;
                return Err(error);
            }
        }
        Ok(())
    }
}

fn entry_for_dir(name: &str, ino: Ino, attrs: DirAttrs) -> ManifestEntry {
    ManifestEntry {
        name: name.to_owned(),
        ino,
        kind: EntryKind::Dir,
        op: EntryOp::Keep,
        from_name: None,
        mode: attrs.mode,
        uid: attrs.uid,
        gid: attrs.gid,
        mtime_ns: attrs.mtime_ns,
        size: 0,
        file_root: base::dir_root(),
        content_hash: None,
        target: None,
    }
}

fn recompute(state: &mut MockState, dir_ino: Ino) {
    let Some(dir) = state.dirs.get(&dir_ino) else {
        return;
    };
    let entries: Vec<ManifestEntry> = dir.entries.values().cloned().collect();
    let version = base::dir_version(NS, dir_ino, &dir.attrs, &entries);
    let dir = state.dirs.get_mut(&dir_ino).unwrap();
    dir.base = MmBase::new(dir.base.epoch, dir.base.dir_seq, version);
}

impl MmRemote for MockRemote {
    fn checkout(&self, request: &CheckoutRequest) -> Result<CheckoutOutcome, RemoteError> {
        self.checkouts.fetch_add(1, Ordering::Relaxed);
        self.fail_if(FailPoint::Checkout)?;
        let state = self.state.lock().unwrap();
        let dir = state
            .dirs
            .get(&request.dir_ino)
            .ok_or(RemoteError::NotFound)?;
        if let Some(if_base) = request.if_base {
            if if_base != dir.base {
                if !self.snapshot_when_stale.load(Ordering::Relaxed) {
                    return Err(RemoteError::BaseChanged {
                        current: dir.base,
                        snapshot_seq: MmSeq::new(state.snapshot_seq),
                    });
                }
            } else {
                return Ok(CheckoutOutcome::NotModified {
                    base: dir.base,
                    snapshot_seq: MmSeq::new(state.snapshot_seq),
                });
            }
        }
        let entries: Vec<CheckoutEntry> = dir
            .entries
            .values()
            .map(|entry| CheckoutEntry {
                name: entry.name.clone(),
                ino: entry.ino,
                kind: entry.kind,
                attrs: DirAttrs {
                    mode: entry.mode,
                    uid: entry.uid,
                    gid: entry.gid,
                    mtime_ns: entry.mtime_ns,
                },
                size: entry.size,
                file_root: entry.file_root,
                content_hash: entry.content_hash,
                target: entry.target.clone(),
            })
            .collect();
        let bodies = if request.bodies {
            entries
                .iter()
                .filter(|entry| entry.kind == EntryKind::File)
                .filter_map(|entry| {
                    dir.bodies
                        .get(&entry.ino)
                        .map(|bytes| super::remote::CheckoutBody {
                            ino: entry.ino,
                            bytes: bytes.clone(),
                        })
                })
                .collect()
        } else {
            Vec::new()
        };
        Ok(CheckoutOutcome::Snapshot(CheckoutSnapshot {
            dir_ino: request.dir_ino,
            base: dir.base,
            snapshot_seq: MmSeq::new(state.snapshot_seq),
            attrs: dir.attrs,
            entries,
            bodies,
        }))
    }

    fn signatures(&self, request: &SignaturesRequest) -> Result<SignaturesResponse, RemoteError> {
        self.fail_if(FailPoint::Any)?;
        let state = self.state.lock().unwrap();
        let dir = state
            .dirs
            .get(&request.dir_ino)
            .ok_or(RemoteError::NotFound)?;
        let mut files = Vec::new();
        for file in &request.files {
            let base_entry = dir.entries.get(&file.name);
            let unchanged = base_entry.is_some_and(|entry| entry.file_root == file.file_root);
            let signature = if unchanged {
                None
            } else {
                match base_entry.and_then(|entry| dir.bodies.get(&entry.ino)) {
                    Some(bytes) => {
                        let size = bytes.len() as u64;
                        Some(
                            sign(Cursor::new(bytes), block_size_for(size))
                                .map_err(|error| RemoteError::Internal(error.to_string()))?,
                        )
                    }
                    None => None,
                }
            };
            files.push(SignatureFilePlan {
                ino: file.ino,
                unchanged,
                signature,
            });
        }
        Ok(SignaturesResponse {
            base: dir.base,
            files,
        })
    }

    fn upload(&self, request: &UploadRequest) -> Result<UploadResponse, RemoteError> {
        self.fail_if(FailPoint::Upload)?;
        let mut state = self.state.lock().unwrap();
        match request {
            UploadRequest::Begin(begin) => {
                let dir = state
                    .dirs
                    .get(&begin.dir_ino)
                    .ok_or(RemoteError::NotFound)?;
                let base = dir.base;
                state.batches.insert(
                    begin.batch_id,
                    MockBatch {
                        state: BatchState::Open,
                        manifest_hash: [0u8; 32],
                        dir_path: begin.dir_path.clone(),
                        result: None,
                    },
                );
                Ok(UploadResponse::Plan(super::remote::UploadPlan {
                    batch_id: begin.batch_id,
                    base,
                    expires_at_ms: 1_000,
                }))
            }
            UploadRequest::Abort(abort) => {
                if let Some(batch) = state.batches.get_mut(&abort.batch_id) {
                    batch.state = BatchState::Aborted;
                    batch.result = None;
                }
                Ok(UploadResponse::Aborted)
            }
            UploadRequest::Commit(commit) => {
                let mut dir = state
                    .dirs
                    .remove(&commit.dir_ino)
                    .ok_or(RemoteError::NotFound)?;
                if commit.base != dir.base {
                    state.dirs.insert(commit.dir_ino, dir);
                    return Err(RemoteError::BaseChanged {
                        current: commit.base,
                        snapshot_seq: MmSeq::new(state.snapshot_seq),
                    });
                }
                let mut by_index: HashMap<u32, &super::remote::UploadFile> = HashMap::new();
                for file in &commit.files {
                    by_index.insert(file.manifest_index, file);
                }
                let mut next: BTreeMap<String, ManifestEntry> = BTreeMap::new();
                for (index, entry) in commit.manifest.iter().enumerate() {
                    let mut entry = entry.clone();
                    match entry.op {
                        EntryOp::Delete => continue,
                        EntryOp::DirRemove => {
                            // The real server refuses to remove a directory
                            // that still has live entries. Model that so a
                            // client-side ordering bug cannot hide here.
                            if state
                                .dirs
                                .get(&entry.ino)
                                .is_some_and(|child| !child.entries.is_empty())
                            {
                                state.dirs.insert(commit.dir_ino, dir);
                                return Err(RemoteError::DirNotEmpty(format!(
                                    "directory {} is not empty",
                                    entry.name
                                )));
                            }
                            state.dirs.remove(&entry.ino);
                            continue;
                        }
                        EntryOp::Rename | EntryOp::DirRename => {
                            if let Some(from) = &entry.from_name {
                                next.remove(from);
                            }
                        }
                        _ => {}
                    }
                    if entry.kind == EntryKind::File {
                        let Some(upload_file) = by_index.get(&(index as u32)) else {
                            state.dirs.insert(commit.dir_ino, dir);
                            return Err(RemoteError::Internal(
                                "missing upload file for file entry".to_owned(),
                            ));
                        };
                        entry.size = upload_file.size;
                        entry.file_root = upload_file.file_root;
                        entry.content_hash = Some(upload_file.content_hash);
                        if !upload_file.unchanged {
                            let Some(source) = &upload_file.source else {
                                state.dirs.insert(commit.dir_ino, dir);
                                return Err(RemoteError::Internal(
                                    "upload file has no source".to_owned(),
                                ));
                            };
                            let bytes = std::fs::read(source)
                                .map_err(|error| RemoteError::Io(error.to_string()))?;
                            if bytes.len() as u64 != upload_file.size {
                                state.dirs.insert(commit.dir_ino, dir);
                                return Err(RemoteError::HashMismatch {
                                    name: entry.name.clone(),
                                    retry_full: true,
                                });
                            }
                            if *blake3::hash(&bytes).as_bytes() != upload_file.content_hash {
                                state.dirs.insert(commit.dir_ino, dir);
                                return Err(RemoteError::HashMismatch {
                                    name: entry.name.clone(),
                                    retry_full: true,
                                });
                            }
                            dir.bodies.insert(entry.ino, bytes);
                        }
                    }
                    next.insert(entry.name.clone(), entry);
                }
                let created_dirs: Vec<(Ino, DirAttrs)> = next
                    .values()
                    .filter(|entry| entry.kind == EntryKind::Dir)
                    .map(|entry| {
                        (
                            entry.ino,
                            DirAttrs {
                                mode: entry.mode,
                                uid: entry.uid,
                                gid: entry.gid,
                                mtime_ns: entry.mtime_ns,
                            },
                        )
                    })
                    .collect();
                dir.entries = next;
                let entries: Vec<ManifestEntry> = dir.entries.values().cloned().collect();
                let version = base::dir_version(NS, commit.dir_ino, &dir.attrs, &entries);
                let dir_seq = dir.base.dir_seq.get() + 1;
                state.snapshot_seq += 1;
                dir.base = MmBase::new(
                    state.epoch,
                    crate::mmap::types::DirSeq::new(dir_seq),
                    version,
                );
                let result = UploadResult {
                    batch_id: commit.batch_id,
                    base: dir.base,
                    snapshot_seq: MmSeq::new(state.snapshot_seq),
                    dir_version: version,
                    entry_count: commit.manifest.len() as u32,
                    bytes: commit.bytes,
                };
                state.batches.insert(
                    commit.batch_id,
                    MockBatch {
                        state: BatchState::Committed,
                        manifest_hash: [0u8; 32],
                        dir_path: commit.dir_path.clone(),
                        result: Some((result.base, result.snapshot_seq, version)),
                    },
                );
                state.dirs.insert(commit.dir_ino, dir);
                let epoch = state.epoch;
                for (ino, attrs) in created_dirs {
                    state.dirs.entry(ino).or_insert_with(|| {
                        let version = base::dir_version(NS, ino, &attrs, &[]);
                        MockDir {
                            attrs,
                            entries: BTreeMap::new(),
                            bodies: HashMap::new(),
                            base: MmBase::new(epoch, crate::mmap::types::DirSeq::new(1), version),
                        }
                    });
                }
                state.commits.push(commit.clone());
                Ok(UploadResponse::Committed(result))
            }
        }
    }

    fn lock(&self, request: &LockRequest) -> Result<LockResponse, RemoteError> {
        self.fail_if(FailPoint::Lock)?;
        let mut state = self.state.lock().unwrap();
        match request {
            LockRequest::Acquire { dir_ino, .. } => {
                let lock_id = LockId::from_bytes([0x5a; 16]);
                state.locks.insert(*dir_ino, lock_id);
                let base = state.dirs.get(dir_ino).ok_or(RemoteError::NotFound)?.base;
                Ok(LockResponse::Granted(GrantedLock {
                    lock_id,
                    dir_ino: *dir_ino,
                    base,
                    expires_at_ms: 1_000,
                }))
            }
            LockRequest::Renew { .. } => Ok(LockResponse::Renewed {
                expires_at_ms: 2_000,
            }),
            LockRequest::Release { lock_id } => {
                state.locks.retain(|_, id| id != lock_id);
                Ok(LockResponse::Released)
            }
        }
    }

    fn file_read(&self, request: &FileReadRequest) -> Result<FileData, RemoteError> {
        self.fail_if(FailPoint::Any)?;
        let state = self.state.lock().unwrap();
        let dir = state
            .dirs
            .get(&request.dir_ino)
            .ok_or(RemoteError::NotFound)?;
        let entry = dir
            .entries
            .get(&request.name)
            .ok_or(RemoteError::NotFound)?;
        if entry.ino != request.ino || entry.file_root != request.file_root {
            return Err(RemoteError::BaseChanged {
                current: dir.base,
                snapshot_seq: MmSeq::new(state.snapshot_seq),
            });
        }
        let body = dir.bodies.get(&entry.ino).ok_or(RemoteError::NotFound)?;
        let start = usize::try_from(request.offset).unwrap_or(usize::MAX);
        if start > body.len() {
            return Err(RemoteError::Internal("range past end".to_owned()));
        }
        let end = start
            .saturating_add(usize::try_from(request.len).unwrap_or(usize::MAX))
            .min(body.len());
        let bytes = body[start..end].to_vec();
        Ok(FileData {
            offset: request.offset,
            range_hash: *blake3::hash(&bytes).as_bytes(),
            bytes,
        })
    }

    fn batch_status(&self, batch_id: BatchId) -> Result<BatchStatus, RemoteError> {
        self.statuses.fetch_add(1, Ordering::Relaxed);
        self.fail_if(FailPoint::BatchStatus)?;
        let state = self.state.lock().unwrap();
        let Some(batch) = state.batches.get(&batch_id) else {
            return Err(RemoteError::NotFound);
        };
        let (snapshot_seq, base_seq_after, dir_version_after) = match batch.result {
            Some((base, seq, version)) => (Some(seq), Some(base.dir_seq), Some(version)),
            None => (None, None, None),
        };
        Ok(BatchStatus {
            batch_id,
            state: batch.state,
            snapshot_seq,
            base_seq_after,
            dir_version_after,
            manifest_hash: batch.manifest_hash,
            dir_path: batch.dir_path.clone(),
        })
    }
}

fn mount(mock: Arc<MockRemote>) -> (tempfile::TempDir, Arc<Shadow>) {
    mount_with_ttl(mock, Duration::ZERO)
}

fn mount_with_ttl(mock: Arc<MockRemote>, ttl: Duration) -> (tempfile::TempDir, Arc<Shadow>) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = ShadowConfig::new(dir.path(), NS);
    config.revalidate_ttl = ttl;
    let shadow = Shadow::open(config, mock).unwrap();
    (dir, Arc::new(shadow))
}

fn root_attr() -> DirAttrs {
    DirAttrs {
        mode: 0o755,
        uid: 0,
        gid: 0,
        mtime_ns: 1,
    }
}

#[test]
fn checkout_materializes_manifest_and_bodies() {
    let mock = MockRemote::new();
    mock.put_file(ROOT_INO, "a", [0x11; 16], b"hello", 0o644);
    let (_dir, shadow) = mount(Arc::clone(&mock));

    shadow.ensure_dir(ROOT_INO, true).unwrap();
    let dir = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
    assert_eq!(dir.record.phase, crate::mmap::types::Phase::Ready);
    assert!(dir.bodies_checked_out);
    assert_eq!(
        std::fs::read(shadow.layout().entry_path(&ROOT_INO, "a")).unwrap(),
        b"hello"
    );
    let file = shadow.db().file_by_name(ROOT_INO, "a").unwrap().unwrap();
    assert_eq!(file.size, 5);
    assert_eq!(file.content_hash, Some(*blake3::hash(b"hello").as_bytes()));

    let lookup = shadow.lookup(1, "a").unwrap();
    assert_eq!(lookup.size, 5);
    let data = shadow.read(lookup.fuse_ino, None, 0, 5).unwrap();
    assert_eq!(data, b"hello");
}

#[test]
fn lookup_manifest_does_not_fetch_body_until_open() {
    let mock = MockRemote::new();
    mock.put_file(ROOT_INO, "a", [0x12; 16], b"content", 0o644);
    let (_dir, shadow) = mount(Arc::clone(&mock));

    let lookup = shadow.lookup(1, "a").unwrap();
    assert_eq!(lookup.size, 7);
    assert!(
        !shadow.layout().object_path(&[0x12; 16], 1).exists(),
        "manifest-only checkout must not download the body"
    );

    let handle = shadow.open_file(lookup.fuse_ino, false).unwrap();
    assert_eq!(
        shadow.read(lookup.fuse_ino, Some(handle.id), 0, 7).unwrap(),
        b"content"
    );
    shadow.release(handle.id).unwrap();
}

#[test]
fn readdir_lists_dot_dotdot_and_children() {
    let mock = MockRemote::new();
    mock.put_file(ROOT_INO, "a", [0x13; 16], b"a", 0o644);
    mock.put_file(ROOT_INO, "b", [0x14; 16], b"b", 0o600);
    let (_dir, shadow) = mount(mock);
    shadow.ensure_dir(ROOT_INO, true).unwrap();

    let items = shadow.readdir(1, 0, false).unwrap();
    let names: Vec<&str> = items.iter().map(|item| item.name.as_str()).collect();
    assert_eq!(names, [".", "..", "a", "b"]);
    assert!(items.iter().all(|item| item.fuse_ino > 0));
}

#[test]
fn child_directory_checkout_does_not_recurse_from_the_parent() {
    let mock = MockRemote::new();
    let child = [0x91; 16];
    mock.add_dir(child, ROOT_INO, "d", root_attr());
    mock.put_file(child, "x", [0x92; 16], b"deep", 0o644);
    let (_dir, shadow) = mount(Arc::clone(&mock));

    shadow.ensure_dir(ROOT_INO, true).unwrap();
    let dir_attr = shadow.lookup(1, "d").unwrap();
    assert_eq!(dir_attr.kind, EntryKind::Dir);
    assert!(
        !shadow.layout().object_path(&[0x92; 16], 1).exists(),
        "parent checkout must not fetch child content"
    );

    shadow.ensure_dir(child, true).unwrap();
    let file = shadow.db().file_by_name(child, "x").unwrap().unwrap();
    assert_eq!(file.size, 4);
    assert_eq!(
        std::fs::read(shadow.layout().entry_path(&child, "x")).unwrap(),
        b"deep"
    );
}

#[test]
fn create_write_and_fsync_commits_a_manifest_and_keeps_dirty_clean() {
    let mock = MockRemote::new();
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();

    let (attr, handle) = shadow
        .create(1, "f", 0o100644, 0, 1000, 1000, true)
        .unwrap();
    assert_eq!(
        shadow.write(attr.fuse_ino, handle.id, 0, b"hello").unwrap(),
        5
    );
    shadow.fsync(attr.fuse_ino, Some(handle.id)).unwrap();

    let commits = mock.commits();
    assert_eq!(commits.len(), 1, "one fsync commits one batch");
    assert!(
        commits[0]
            .manifest
            .iter()
            .any(|entry| entry.name == "f" && entry.op == EntryOp::Put)
    );
    assert_eq!(mock.body(ROOT_INO, "f").unwrap(), b"hello");

    let dir = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
    assert!(dir.clean());
    assert_eq!(dir.record.base, mock.base(ROOT_INO));

    shadow.fsync(attr.fuse_ino, Some(handle.id)).unwrap();
    assert_eq!(mock.commits().len(), 1, "clean directory uploads nothing");
    shadow.release(handle.id).unwrap();
}

#[test]
fn fsync_lock_conflict_returns_eagain_and_keeps_dirty() {
    let mock = MockRemote::new();
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();
    let (attr, handle) = shadow
        .create(1, "f", 0o100644, 0, 1000, 1000, true)
        .unwrap();
    shadow.write(attr.fuse_ino, handle.id, 0, b"kept").unwrap();

    mock.set_failure(
        FailPoint::Lock,
        RemoteError::LockHeld {
            owner: "other".to_owned(),
            expires_at_ms: 1,
            retry_after_ms: 1,
        },
    );
    let error = shadow.fsync(attr.fuse_ino, Some(handle.id)).unwrap_err();
    assert_eq!(error.errno(), libc::EAGAIN);
    let dir = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
    assert!(!dir.clean(), "dirty generation survives the lock conflict");
    assert_eq!(mock.commits().len(), 0);
    assert_eq!(
        std::fs::read(shadow.layout().entry_path(&ROOT_INO, "f")).unwrap(),
        b"kept"
    );

    mock.clear_failure();
    shadow.fsync(attr.fuse_ino, Some(handle.id)).unwrap();
    assert_eq!(mock.commits().len(), 1);
    assert_eq!(mock.body(ROOT_INO, "f").unwrap(), b"kept");
    shadow.release(handle.id).unwrap();
}

#[test]
fn fsync_base_change_returns_eagain_and_keeps_dirty() {
    let mock = MockRemote::new();
    // A long TTL keeps the fsync's pre-check from consuming the injected
    // failure; the revalidation after the upload lease is the target.
    let (_dir, shadow) = mount_with_ttl(Arc::clone(&mock), Duration::from_secs(60));
    shadow.ensure_dir(ROOT_INO, true).unwrap();
    let (attr, handle) = shadow
        .create(1, "f", 0o100644, 0, 1000, 1000, true)
        .unwrap();
    shadow.write(attr.fuse_ino, handle.id, 0, b"dirty").unwrap();

    mock.set_failure(
        FailPoint::Checkout,
        RemoteError::BaseChanged {
            current: MmBase::new(1, crate::mmap::types::DirSeq::new(9), [9; 32]),
            snapshot_seq: MmSeq::new(9),
        },
    );
    let error = shadow.fsync(attr.fuse_ino, Some(handle.id)).unwrap_err();
    assert_eq!(error.errno(), libc::EAGAIN);
    let dir = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
    assert!(!dir.clean());
    assert_eq!(mock.commits().len(), 0);
    shadow.release(handle.id).unwrap();
}

#[test]
fn remote_refresh_creates_a_new_version_and_old_fd_keeps_old_bytes() {
    let mock = MockRemote::new();
    mock.put_file(ROOT_INO, "f", [0x21; 16], b"one", 0o644);
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();
    let old = shadow.lookup(1, "f").unwrap();
    let old_handle = shadow.open_file(old.fuse_ino, false).unwrap();
    shadow.release(old_handle.id).unwrap();

    mock.put_file(ROOT_INO, "f", [0x21; 16], b"two", 0o644);
    shadow.mark_stale(ROOT_INO).unwrap();
    let new = shadow.lookup(1, "f").unwrap();
    assert_ne!(old.fuse_ino, new.fuse_ino, "versioned inode must change");
    assert_eq!(new.size, 3);
    assert_eq!(
        shadow.read(old.fuse_ino, None, 0, 3).unwrap(),
        b"one",
        "old inode keeps the old object"
    );
    assert_eq!(shadow.read(new.fuse_ino, None, 0, 3).unwrap(), b"two");

    // Old lookup references were released explicitly and on the first
    // lookup; collect now removes the old object.
    shadow.forget(old.fuse_ino, 1).unwrap();
    shadow.collect_garbage().unwrap();
    assert!(!shadow.layout().object_path(&[0x21; 16], 1).exists());
    assert!(shadow.layout().object_path(&[0x21; 16], 2).exists());
}

#[test]
fn unlink_keeps_an_open_descriptor_readable() {
    let mock = MockRemote::new();
    mock.put_file(ROOT_INO, "f", [0x22; 16], b"alive", 0o644);
    let (_dir, shadow) = mount(mock);
    shadow.ensure_dir(ROOT_INO, true).unwrap();
    let attr = shadow.lookup(1, "f").unwrap();
    let handle = shadow.open_file(attr.fuse_ino, false).unwrap();

    shadow.unlink(1, "f").unwrap();
    assert!(shadow.lookup(1, "f").is_err());
    assert_eq!(
        shadow.read(attr.fuse_ino, Some(handle.id), 0, 5).unwrap(),
        b"alive"
    );
    shadow.release(handle.id).unwrap();
}

#[test]
fn concurrent_opens_single_flight_one_checkout() {
    let mock = MockRemote::new();
    mock.put_file(ROOT_INO, "a", [0x31; 16], b"x", 0o644);
    // A non-zero TTL makes the completed snapshot the fast path for every
    // waiter; TTL zero intentionally revalidates on every access.
    let (_dir, shadow) = mount_with_ttl(Arc::clone(&mock), Duration::from_secs(60));
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let shadow = Arc::clone(&shadow);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            shadow.ensure_dir(ROOT_INO, true).unwrap();
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
    assert_eq!(
        mock.checkouts.load(Ordering::Relaxed),
        1,
        "one checkout serves every concurrent opener"
    );
}

#[test]
fn mkdir_rmdir_and_symlink_stay_local_until_fsync() {
    let mock = MockRemote::new();
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();

    let child = shadow.mkdir(1, "d", 0o755, 0, 1000, 1000).unwrap();
    let link = shadow.symlink(1, "l", b"d", 1000, 1000).unwrap();
    assert_eq!(shadow.readlink(link.fuse_ino).unwrap(), b"d");
    assert!(shadow.db().files(child.ino).unwrap().is_empty());
    assert_eq!(mock.commits().len(), 0, "mkdir alone does not upload");

    // A file inside the local-only child cannot upload before its parent
    // structure commits; fsync reports EAGAIN and keeps the data.
    let (_attr, handle) = shadow
        .create(child.fuse_ino, "f", 0o100644, 0, 1000, 1000, true)
        .unwrap();
    shadow.write(child.fuse_ino, handle.id, 0, b"x").unwrap();
    assert_eq!(
        shadow
            .fsync(child.fuse_ino, Some(handle.id))
            .unwrap_err()
            .errno(),
        libc::EAGAIN
    );
    shadow.release(handle.id).unwrap();

    shadow.rmdir(1, "d").unwrap_err();
    shadow.unlink(1, "l").unwrap();
}

#[test]
fn fsync_parent_snapshot_keeps_a_local_only_child_directory() {
    let mock = MockRemote::new();
    // A long TTL skips the pre-check; the upload revalidation takes the
    // snapshot, exactly where the production tombstone happened.
    let (_dir, shadow) = mount_with_ttl(Arc::clone(&mock), Duration::from_secs(60));
    shadow.ensure_dir(ROOT_INO, true).unwrap();

    // Another client changes the directory after the local checkout. The
    // empty snapshot this produces must not look like "every child removed".
    mock.touch_dir(ROOT_INO);
    mock.set_snapshot_when_stale(true);

    let child = shadow.mkdir(1, "d", 0o755, 0, 1000, 1000).unwrap();
    let (file, handle) = shadow
        .create(child.fuse_ino, "f", 0o100644, 0, 1000, 1000, true)
        .unwrap();
    shadow.write(file.fuse_ino, handle.id, 0, b"x").unwrap();

    // The snapshot must keep the local-only child, and the parent batch must
    // carry exactly that child.
    shadow.fsyncdir(1).unwrap();
    assert_eq!(shadow.lookup(1, "d").unwrap().kind, EntryKind::Dir);
    let entry = shadow.db().file_by_name(ROOT_INO, "d").unwrap().unwrap();
    assert!(!entry.deleted, "a local-only child is not a removal");
    assert!(
        !shadow
            .db()
            .shadow_dir(child.ino)
            .unwrap()
            .unwrap()
            .local_only,
        "the committed parent clears local_only"
    );
    let commits = mock.commits();
    assert_eq!(commits.len(), 1);
    assert_eq!(commits[0].manifest.len(), 1);
    assert_eq!(commits[0].manifest[0].name, "d");

    // The child now uploads the file it holds.
    shadow.ensure_dir(child.ino, false).unwrap();
    shadow.fsyncdir(child.fuse_ino).unwrap();
    assert_eq!(mock.commits().len(), 2);
    assert_eq!(mock.body(child.ino, "f").unwrap(), b"x");

    // Repeated fsync is idempotent.
    shadow.fsyncdir(1).unwrap();
    shadow.fsyncdir(child.fuse_ino).unwrap();
    assert_eq!(mock.commits().len(), 2);
    shadow.release(handle.id).unwrap();
}

#[test]
fn fsync_parent_snapshot_keeps_a_local_only_file_and_symlink() {
    let mock = MockRemote::new();
    let (_dir, shadow) = mount_with_ttl(Arc::clone(&mock), Duration::from_secs(60));
    shadow.ensure_dir(ROOT_INO, true).unwrap();

    mock.touch_dir(ROOT_INO);
    mock.set_snapshot_when_stale(true);

    let (file, handle) = shadow
        .create(1, "f", 0o100644, 0, 1000, 1000, true)
        .unwrap();
    shadow.write(file.fuse_ino, handle.id, 0, b"x").unwrap();
    let link = shadow.symlink(1, "l", b"f", 1000, 1000).unwrap();

    shadow.fsyncdir(1).unwrap();
    assert_eq!(shadow.lookup(1, "f").unwrap().kind, EntryKind::File);
    assert_eq!(shadow.lookup(1, "l").unwrap().kind, EntryKind::Symlink);
    assert_eq!(shadow.readlink(link.fuse_ino).unwrap(), b"f");
    let commits = mock.commits();
    assert_eq!(commits.len(), 1);
    let names: Vec<&str> = commits[0]
        .manifest
        .iter()
        .map(|entry| entry.name.as_str())
        .collect();
    assert_eq!(names, ["f", "l"]);
    shadow.release(handle.id).unwrap();
}

#[test]
fn parent_commit_publishes_a_local_child_before_the_child_uploads() {
    let mock = MockRemote::new();
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();

    let child = shadow.mkdir(1, "d", 0o755, 0, 1000, 1000).unwrap();
    let (trigger, trigger_handle) = shadow
        .create(1, "trigger", 0o100644, 0, 1000, 1000, true)
        .unwrap();
    shadow
        .write(trigger.fuse_ino, trigger_handle.id, 0, b"x")
        .unwrap();
    shadow
        .fsync(trigger.fuse_ino, Some(trigger_handle.id))
        .unwrap();
    assert_eq!(mock.commits().len(), 1);

    let (file, handle) = shadow
        .create(child.fuse_ino, "inside", 0o100644, 0, 1000, 1000, true)
        .unwrap();
    shadow.write(file.fuse_ino, handle.id, 0, b"child").unwrap();
    shadow.fsync(file.fuse_ino, Some(handle.id)).unwrap();
    assert_eq!(mock.commits().len(), 2, "child directory now uploads");
    assert_eq!(mock.body(child.ino, "inside").unwrap(), b"child");
    shadow.release(handle.id).unwrap();
    shadow.release(trigger_handle.id).unwrap();
}

#[test]
fn close_uploads_the_last_dirty_reference_once() {
    let mock = MockRemote::new();
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();

    let (attr, handle) = shadow
        .create(1, "f", 0o100644, 0, 1000, 1000, true)
        .unwrap();
    shadow.write(attr.fuse_ino, handle.id, 0, b"hello").unwrap();

    // `flush` may run many times before the final close; none of them upload.
    shadow.flush(handle.id, Some(7)).unwrap();
    shadow.flush(handle.id, Some(7)).unwrap();
    assert_eq!(mock.commits().len(), 0, "flush never uploads");

    // One reference is not the last one: nothing uploads yet.
    let second = shadow.open_file(attr.fuse_ino, false).unwrap();
    shadow.release(handle.id).unwrap();
    assert_eq!(mock.commits().len(), 0, "only the last close uploads");

    shadow.release(second.id).unwrap();
    let commits = mock.commits();
    assert_eq!(commits.len(), 1, "the last close commits the batch");
    assert!(
        commits[0]
            .manifest
            .iter()
            .any(|entry| entry.name == "f" && entry.op == EntryOp::Put)
    );
    assert_eq!(mock.body(ROOT_INO, "f").unwrap(), b"hello");

    // A repeated close is a no-op.
    shadow.release(handle.id).unwrap();
    assert_eq!(mock.commits().len(), 1);
}

#[test]
fn close_conflict_keeps_dirty_and_reports_success() {
    let cases = [
        (
            FailPoint::Upload,
            RemoteError::BaseChanged {
                current: MmBase::new(1, crate::mmap::types::DirSeq::new(9), [9; 32]),
                snapshot_seq: MmSeq::new(9),
            },
        ),
        (
            FailPoint::Lock,
            RemoteError::LockHeld {
                owner: "other".to_owned(),
                expires_at_ms: 1,
                retry_after_ms: 1,
            },
        ),
    ];
    for (point, error) in cases {
        let mock = MockRemote::new();
        let (_dir, shadow) = mount(Arc::clone(&mock));
        shadow.ensure_dir(ROOT_INO, true).unwrap();
        let (attr, handle) = shadow
            .create(1, "f", 0o100644, 0, 1000, 1000, true)
            .unwrap();
        shadow.write(attr.fuse_ino, handle.id, 0, b"kept").unwrap();

        mock.set_failure(point, error);
        shadow.release(handle.id).unwrap();
        let dir = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
        assert!(!dir.clean(), "a failed close keeps the dirty generation");
        assert_eq!(mock.commits().len(), 0);

        // The next explicit fsync retries and succeeds.
        mock.clear_failure();
        shadow.fsyncdir(1).unwrap();
        assert_eq!(mock.commits().len(), 1);
        assert_eq!(mock.body(ROOT_INO, "f").unwrap(), b"kept");
    }
}

#[test]
fn write_after_close_uploads_new_content_on_fsync() {
    let mock = MockRemote::new();
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();

    let (attr, handle) = shadow
        .create(1, "f", 0o100644, 0, 1000, 1000, true)
        .unwrap();
    shadow.write(attr.fuse_ino, handle.id, 0, b"one").unwrap();
    shadow.release(handle.id).unwrap();
    assert_eq!(mock.body(ROOT_INO, "f").unwrap(), b"one");
    assert!(
        shadow
            .layout()
            .object_path(&attr.ino, attr.version)
            .exists(),
        "close keeps the current object for a live mapping"
    );

    // The kernel may still hold the mapping and send writes with the old fh.
    shadow.write(attr.fuse_ino, handle.id, 0, b"two").unwrap();
    shadow.fsync(attr.fuse_ino, Some(handle.id)).unwrap();
    assert_eq!(mock.body(ROOT_INO, "f").unwrap(), b"two");
    assert_eq!(mock.commits().len(), 2);

    // A write without a handle takes the same fallback path.
    shadow.write(attr.fuse_ino, handle.id, 3, b"!").unwrap();
    shadow.fsync(attr.fuse_ino, None).unwrap();
    assert_eq!(mock.body(ROOT_INO, "f").unwrap(), b"two!");
    assert_eq!(mock.commits().len(), 3);
}

#[test]
fn close_commits_the_ancestor_chain_before_the_owning_directory() {
    let mock = MockRemote::new();
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();

    let a = shadow.mkdir(1, "a", 0o755, 0, 1000, 1000).unwrap();
    let b = shadow.mkdir(a.fuse_ino, "b", 0o755, 0, 1000, 1000).unwrap();
    let (file, handle) = shadow
        .create(b.fuse_ino, "f", 0o100644, 0, 1000, 1000, true)
        .unwrap();
    shadow.write(file.fuse_ino, handle.id, 0, b"deep").unwrap();

    shadow.release(handle.id).unwrap();
    let commits = mock.commits();
    assert_eq!(commits.len(), 3, "root, a, then b");
    assert_eq!(commits[0].dir_path, "/");
    assert!(
        commits[0]
            .manifest
            .iter()
            .any(|entry| entry.name == "a" && entry.op == EntryOp::DirAdd)
    );
    assert_eq!(commits[1].dir_path, "/a");
    assert!(commits[1].manifest.iter().any(|entry| entry.name == "b"));
    assert_eq!(commits[2].dir_path, "/a/b");
    assert_eq!(mock.body(b.ino, "f").unwrap(), b"deep");
    assert!(shadow.lookup(1, "a").is_ok());
    assert!(shadow.lookup(a.fuse_ino, "b").is_ok());
}

#[test]
fn last_releasedir_commits_a_dirty_directory_once() {
    let mock = MockRemote::new();
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();

    shadow.mkdir(1, "d", 0o755, 0, 1000, 1000).unwrap();
    shadow.opendir(1).unwrap();
    assert_eq!(mock.commits().len(), 0, "mkdir alone does not upload");

    shadow.releasedir(1).unwrap();
    let commits = mock.commits();
    assert_eq!(commits.len(), 1);
    assert!(
        commits[0]
            .manifest
            .iter()
            .any(|entry| entry.name == "d" && entry.op == EntryOp::DirAdd)
    );

    shadow.releasedir(1).unwrap();
    assert_eq!(mock.commits().len(), 1, "a repeated close is a no-op");
}

#[test]
fn upload_manifest_reflects_delete_and_attrs() {
    let mock = MockRemote::new();
    mock.put_file(ROOT_INO, "keep", [0x41; 16], b"same", 0o644);
    mock.put_file(ROOT_INO, "drop", [0x42; 16], b"gone", 0o644);
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();

    shadow.unlink(1, "drop").unwrap();
    let keep = shadow.lookup(1, "keep").unwrap();
    let handle = shadow.open_file(keep.fuse_ino, true).unwrap();
    shadow
        .setattr(
            keep.fuse_ino,
            Some(handle.id),
            super::AttrChange {
                mode: Some(0o600),
                ..super::AttrChange::default()
            },
        )
        .unwrap();
    shadow.fsync(keep.fuse_ino, Some(handle.id)).unwrap();

    let commits = mock.commits();
    assert_eq!(commits.len(), 1);
    let manifest = &commits[0].manifest;
    assert!(
        manifest
            .iter()
            .any(|entry| entry.name == "drop" && entry.op == EntryOp::Delete)
    );
    assert!(
        manifest
            .iter()
            .any(|entry| entry.name == "keep" && entry.op == EntryOp::Keep && entry.mode == 0o600)
    );
    assert!(mock.body(ROOT_INO, "drop").is_none());
    assert_eq!(mock.body(ROOT_INO, "keep").unwrap(), b"same");
    shadow.release(handle.id).unwrap();
}

fn test_ino(index: u32) -> Ino {
    let mut ino = [0u8; 16];
    ino[0..4].copy_from_slice(&(index + 1).to_le_bytes());
    ino
}

/// Write `body` through a fresh writable handle and restore the checkout
/// mtime, so only a content hash can distinguish the result from a clean
/// checkout.
fn rewrite_and_restore_mtime(shadow: &Shadow, fuse_ino: u64, body: &[u8], mtime_ns: i64) {
    let handle = shadow.open_file(fuse_ino, true).unwrap();
    shadow.write(fuse_ino, handle.id, 0, body).unwrap();
    shadow
        .setattr(
            fuse_ino,
            Some(handle.id),
            super::AttrChange {
                mtime_ns: Some(mtime_ns),
                ..super::AttrChange::default()
            },
        )
        .unwrap();
    shadow.release(handle.id).unwrap();
}

#[test]
fn noop_fsync_after_rewriting_same_bytes_and_mtime_uploads_nothing() {
    let mock = MockRemote::new();
    mock.put_file(ROOT_INO, "a", [0xb1; 16], b"hello", 0o644);
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();
    let attr = shadow.lookup(1, "a").unwrap();
    let handle = shadow.open_file(attr.fuse_ino, true).unwrap();
    shadow.write(attr.fuse_ino, handle.id, 0, b"hello").unwrap();
    shadow
        .setattr(
            attr.fuse_ino,
            Some(handle.id),
            super::AttrChange {
                mtime_ns: Some(10),
                ..super::AttrChange::default()
            },
        )
        .unwrap();
    let seq = mock.snapshot_seq();
    let checkouts = mock.checkouts.load(Ordering::Relaxed);

    shadow.fsync(attr.fuse_ino, Some(handle.id)).unwrap();

    assert_eq!(mock.batch_count(), 0, "a no-op checkin opens no batch");
    assert_eq!(mock.commits().len(), 0);
    assert_eq!(
        mock.checkouts.load(Ordering::Relaxed),
        checkouts,
        "a no-op checkin sends no network request at all"
    );
    assert_eq!(mock.snapshot_seq(), seq, "snapshot_seq must not advance");
    let dir = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
    assert!(dir.clean(), "the directory is clean after suppression");
    let file = shadow.db().file_by_name(ROOT_INO, "a").unwrap().unwrap();
    let version = shadow
        .db()
        .shadow_version(file.ino, file.version)
        .unwrap()
        .unwrap();
    assert_eq!(version.dirty_gen, 0);
    assert_eq!(version.state, VersionState::Clean);

    // A second checkin is a plain no-op.
    shadow.fsync(attr.fuse_ino, Some(handle.id)).unwrap();
    assert_eq!(mock.batch_count(), 0);
    shadow.release(handle.id).unwrap();
    assert_eq!(mock.commits().len(), 0, "close must stay local too");
}

#[test]
fn noop_close_after_rewriting_same_bytes_and_mtime_uploads_nothing() {
    let mock = MockRemote::new();
    mock.put_file(ROOT_INO, "a", [0xb2; 16], b"hello", 0o644);
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();
    let attr = shadow.lookup(1, "a").unwrap();

    rewrite_and_restore_mtime(&shadow, attr.fuse_ino, b"hello", 10);

    assert_eq!(mock.batch_count(), 0);
    assert_eq!(mock.commits().len(), 0);
    assert!(shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap().clean());
}

#[test]
fn same_size_different_content_with_same_mtime_uploads() {
    let mock = MockRemote::new();
    mock.put_file(ROOT_INO, "a", [0xb3; 16], b"hello", 0o644);
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();
    let attr = shadow.lookup(1, "a").unwrap();
    let handle = shadow.open_file(attr.fuse_ino, true).unwrap();
    shadow.write(attr.fuse_ino, handle.id, 0, b"world").unwrap();
    shadow
        .setattr(
            attr.fuse_ino,
            Some(handle.id),
            super::AttrChange {
                mtime_ns: Some(10),
                ..super::AttrChange::default()
            },
        )
        .unwrap();
    let seq = mock.snapshot_seq();

    shadow.fsync(attr.fuse_ino, Some(handle.id)).unwrap();

    assert_eq!(mock.batch_count(), 1, "the hash must reveal the change");
    assert_eq!(mock.body(ROOT_INO, "a").unwrap(), b"world");
    assert!(mock.snapshot_seq() > seq);
    shadow.release(handle.id).unwrap();
}

#[test]
fn mtime_only_change_uploads() {
    let mock = MockRemote::new();
    mock.put_file(ROOT_INO, "a", [0xb4; 16], b"hello", 0o644);
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();
    let attr = shadow.lookup(1, "a").unwrap();
    let handle = shadow.open_file(attr.fuse_ino, true).unwrap();
    shadow
        .setattr(
            attr.fuse_ino,
            Some(handle.id),
            super::AttrChange {
                mtime_ns: Some(11),
                ..super::AttrChange::default()
            },
        )
        .unwrap();

    shadow.fsync(attr.fuse_ino, Some(handle.id)).unwrap();

    let commits = mock.commits();
    assert_eq!(commits.len(), 1);
    assert_eq!(commits[0].manifest[0].mtime_ns, 11);
    assert_eq!(mock.body(ROOT_INO, "a").unwrap(), b"hello");
    shadow.release(handle.id).unwrap();
}

#[test]
fn create_then_unlink_after_restoring_directory_mtime_does_not_commit() {
    let mock = MockRemote::new();
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();

    let (attr, handle) = shadow
        .create(1, "x", 0o100644, 0, 1000, 1000, true)
        .unwrap();
    shadow
        .write(attr.fuse_ino, handle.id, 0, b"temporary")
        .unwrap();
    shadow.unlink(1, "x").unwrap();
    shadow
        .setattr(
            1,
            None,
            super::AttrChange {
                mtime_ns: Some(1),
                ..super::AttrChange::default()
            },
        )
        .unwrap();

    shadow.release(handle.id).unwrap();

    assert_eq!(mock.batch_count(), 0);
    assert_eq!(mock.commits().len(), 0);
    let dir = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
    assert!(dir.clean());
    if let Some(version) = shadow.db().shadow_version(attr.ino, attr.version).unwrap() {
        assert_eq!(version.dirty_gen, 0, "the tombstone version is collected");
    }
}

#[test]
fn local_only_parent_skips_while_the_child_uploads() {
    let mock = MockRemote::new();
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();

    let child = shadow.mkdir(1, "d", 0o755, 0, 1000, 1000).unwrap();
    shadow.fsyncdir(1).unwrap();
    assert_eq!(mock.commits().len(), 1);

    let (file, handle) = shadow
        .create(child.fuse_ino, "x", 0o100644, 0, 1000, 1000, true)
        .unwrap();
    shadow.write(file.fuse_ino, handle.id, 0, b"x").unwrap();

    // The parent has no direct change, so its checkin must not add a batch.
    shadow.fsyncdir(1).unwrap();
    assert_eq!(mock.commits().len(), 1);

    shadow.fsync(file.fuse_ino, Some(handle.id)).unwrap();
    assert_eq!(mock.commits().len(), 2, "only the child uploads");
    assert_eq!(mock.body(child.ino, "x").unwrap(), b"x");
    shadow.release(handle.id).unwrap();
}

#[test]
fn noop_check_hashes_only_the_dirty_file_among_a_thousand() {
    let mock = MockRemote::new();
    for index in 0..1000u32 {
        let name = format!("f{index:04}");
        mock.put_file(ROOT_INO, &name, test_ino(index), b"x", 0o644);
    }
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();

    let attr = shadow.lookup(1, "f0500").unwrap();
    let handle = shadow.open_file(attr.fuse_ino, true).unwrap();
    shadow.write(attr.fuse_ino, handle.id, 0, b"x").unwrap();
    shadow
        .setattr(
            attr.fuse_ino,
            Some(handle.id),
            super::AttrChange {
                mtime_ns: Some(10),
                ..super::AttrChange::default()
            },
        )
        .unwrap();
    let seq = mock.snapshot_seq();
    super::noop::HASHED_FILES.with(|count| count.set(0));

    shadow.fsync(attr.fuse_ino, Some(handle.id)).unwrap();

    let hashed = super::noop::HASHED_FILES.with(std::cell::Cell::get);
    assert_eq!(hashed, 1, "clean bodies are never hashed");
    assert_eq!(mock.batch_count(), 0);
    assert_eq!(mock.snapshot_seq(), seq);
    shadow.release(handle.id).unwrap();
}

#[test]
#[ignore = "perf: measures the no-op check over 1000 entries"]
fn noop_checkin_cost_for_a_thousand_entries() {
    let mock = MockRemote::new();
    for index in 0..1000u32 {
        let name = format!("f{index:04}");
        mock.put_file(ROOT_INO, &name, test_ino(index), b"x", 0o644);
    }
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();
    let dir = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();

    const SAMPLES: u32 = 100;
    let mut clean = Duration::ZERO;
    for _ in 0..SAMPLES {
        let started = Instant::now();
        let check = shadow.check_noop(&dir).unwrap();
        clean += started.elapsed();
        assert!(check.suppressed());
    }

    let attr = shadow.lookup(1, "f0500").unwrap();
    let handle = shadow.open_file(attr.fuse_ino, true).unwrap();
    shadow.write(attr.fuse_ino, handle.id, 0, b"x").unwrap();
    shadow
        .setattr(
            attr.fuse_ino,
            Some(handle.id),
            super::AttrChange {
                mtime_ns: Some(10),
                ..super::AttrChange::default()
            },
        )
        .unwrap();
    let mut dirty = Duration::ZERO;
    for _ in 0..SAMPLES {
        let started = Instant::now();
        let check = shadow.check_noop(&dir).unwrap();
        dirty += started.elapsed();
        assert!(check.suppressed());
    }
    eprintln!(
        "noop check, 1000 entries: clean {:?}/check, one dirty file {:?}/check",
        clean / SAMPLES,
        dirty / SAMPLES
    );
    shadow.release(handle.id).unwrap();
}

#[test]
fn concurrent_write_after_a_noop_plan_is_not_lost() {
    let mock = MockRemote::new();
    mock.put_file(ROOT_INO, "a", [0xb5; 16], b"hello", 0o644);
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();
    let attr = shadow.lookup(1, "a").unwrap();
    let handle = shadow.open_file(attr.fuse_ino, true).unwrap();
    shadow.write(attr.fuse_ino, handle.id, 0, b"hello").unwrap();
    shadow
        .setattr(
            attr.fuse_ino,
            Some(handle.id),
            super::AttrChange {
                mtime_ns: Some(10),
                ..super::AttrChange::default()
            },
        )
        .unwrap();

    let dir = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
    let check = shadow.check_noop(&dir).unwrap();
    assert!(check.suppressed(), "the first state is a proved no-op");

    // A write lands after the check but before the dirty state is cleared.
    shadow.write(attr.fuse_ino, handle.id, 0, b"world").unwrap();
    let published = shadow
        .db()
        .publish_noop(ROOT_INO, dir.dirty_gen, &dir.record.base, &check.clears)
        .unwrap();
    assert!(!published, "the generation guard rejects the stale plan");

    shadow.fsync(attr.fuse_ino, Some(handle.id)).unwrap();
    assert_eq!(mock.body(ROOT_INO, "a").unwrap(), b"world");
    assert_eq!(mock.batch_count(), 1, "the concurrent write is uploaded");
    shadow.release(handle.id).unwrap();
}

#[test]
fn missing_baseline_hash_uploads_conservatively() {
    let mock = MockRemote::new();
    mock.put_file(ROOT_INO, "a", [0xb6; 16], b"hello", 0o644);
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();

    let conn = rusqlite::Connection::open(shadow.db().path()).unwrap();
    conn.execute(
        "UPDATE mm_base SET content_hash = NULL
         WHERE namespace = ?1 AND name = 'a'",
        rusqlite::params![NS],
    )
    .unwrap();
    drop(conn);

    let attr = shadow.lookup(1, "a").unwrap();
    let handle = shadow.open_file(attr.fuse_ino, true).unwrap();
    shadow.write(attr.fuse_ino, handle.id, 0, b"hello").unwrap();
    shadow
        .setattr(
            attr.fuse_ino,
            Some(handle.id),
            super::AttrChange {
                mtime_ns: Some(10),
                ..super::AttrChange::default()
            },
        )
        .unwrap();

    shadow.fsync(attr.fuse_ino, Some(handle.id)).unwrap();

    assert_eq!(mock.batch_count(), 1, "no baseline hash means upload");
    shadow.release(handle.id).unwrap();
}

#[test]
fn rmdir_commits_pending_child_deletes_before_the_parent_batch() {
    let mock = MockRemote::new();
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();

    let child = shadow.mkdir(1, "d", 0o755, 0, 1000, 1000).unwrap();
    let (file, handle) = shadow
        .create(child.fuse_ino, "f", 0o100644, 0, 1000, 1000, true)
        .unwrap();
    shadow.write(file.fuse_ino, handle.id, 0, b"x").unwrap();
    shadow.release(handle.id).unwrap();
    assert_eq!(
        mock.commits().len(),
        2,
        "root publishes d, then d publishes f"
    );
    assert_eq!(mock.body(child.ino, "f").unwrap(), b"x");

    shadow.unlink(child.fuse_ino, "f").unwrap();
    assert_eq!(mock.commits().len(), 2, "unlink alone stays local");

    shadow.rmdir(1, "d").unwrap();
    let commits = mock.commits();
    assert_eq!(
        commits.len(),
        3,
        "rmdir commits the child before deleting it"
    );
    assert_eq!(commits[2].dir_path, "/d");
    assert!(
        commits[2]
            .manifest
            .iter()
            .any(|entry| entry.name == "f" && entry.op == EntryOp::Delete)
    );
    assert_eq!(
        mock.dir_entry_count(child.ino),
        Some(0),
        "the server side child is empty before the parent batch"
    );
    assert!(mock.body(child.ino, "f").is_none());
    assert_eq!(
        shadow
            .db()
            .shadow_version(file.ino, file.version)
            .unwrap()
            .unwrap()
            .dirty_gen,
        0,
        "the committed tombstone is no longer dirty"
    );

    shadow.fsyncdir(1).unwrap();
    let commits = mock.commits();
    assert_eq!(commits.len(), 4, "then the parent removes the empty child");
    assert_eq!(commits[3].dir_path, "/");
    assert!(
        commits[3]
            .manifest
            .iter()
            .any(|entry| entry.name == "d" && entry.op == EntryOp::DirRemove)
    );
    assert!(!mock.dir_exists(child.ino));
    assert!(shadow.lookup(1, "d").is_err());
}

#[test]
fn rmdir_failure_keeps_the_directory_and_its_pending_delete() {
    let mock = MockRemote::new();
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();

    let child = shadow.mkdir(1, "d", 0o755, 0, 1000, 1000).unwrap();
    let (file, handle) = shadow
        .create(child.fuse_ino, "f", 0o100644, 0, 1000, 1000, true)
        .unwrap();
    shadow.write(file.fuse_ino, handle.id, 0, b"x").unwrap();
    shadow.release(handle.id).unwrap();
    shadow.unlink(child.fuse_ino, "f").unwrap();

    mock.set_failure(
        FailPoint::Lock,
        RemoteError::LockHeld {
            owner: "other".to_owned(),
            expires_at_ms: 1,
            retry_after_ms: 1,
        },
    );
    let error = shadow.rmdir(1, "d").unwrap_err();
    assert_eq!(error.errno(), libc::EAGAIN);
    assert_eq!(
        mock.commits().len(),
        2,
        "the failed child batch did not commit"
    );
    assert!(shadow.lookup(1, "d").is_ok(), "the directory survives");
    assert!(
        !shadow.db().shadow_dir(child.ino).unwrap().unwrap().clean(),
        "the child dirty generation survives"
    );
    let tombstone = shadow.db().file_by_name(child.ino, "f").unwrap().unwrap();
    assert!(tombstone.deleted, "the pending unlink was not dropped");

    mock.clear_failure();
    shadow.rmdir(1, "d").unwrap();
    shadow.fsyncdir(1).unwrap();
    assert!(!mock.dir_exists(child.ino));
    assert!(shadow.lookup(1, "d").is_err());
}

#[test]
fn close_commits_the_parent_after_the_owning_directory_was_removed() {
    let mock = MockRemote::new();
    let (_dir, shadow) = mount(Arc::clone(&mock));
    shadow.ensure_dir(ROOT_INO, true).unwrap();

    let child = shadow.mkdir(1, "d", 0o755, 0, 1000, 1000).unwrap();
    let (file, handle) = shadow
        .create(child.fuse_ino, "f", 0o100644, 0, 1000, 1000, true)
        .unwrap();
    shadow.write(file.fuse_ino, handle.id, 0, b"x").unwrap();
    shadow.release(handle.id).unwrap();
    assert_eq!(mock.commits().len(), 2);
    let handle = shadow.open_file(file.fuse_ino, true).unwrap();

    // Remove the file and its directory while the file handle stays open.
    shadow.unlink(child.fuse_ino, "f").unwrap();
    shadow.rmdir(1, "d").unwrap();
    assert_eq!(mock.commits().len(), 3);
    assert!(shadow.db().shadow_dir(child.ino).unwrap().is_none());

    // The close names a removed directory; it must still commit the root
    // batch that drops that directory.
    shadow.release(handle.id).unwrap();
    assert_eq!(mock.commits().len(), 4);
    assert!(!mock.dir_exists(child.ino));
    assert!(shadow.lookup(1, "d").is_err());
    assert!(shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap().clean());
}

#[test]
fn db_version_mapping_and_refcount_are_stable() {
    let mock = MockRemote::new();
    mock.put_file(ROOT_INO, "f", [0x51; 16], b"body", 0o644);
    let (_dir, shadow) = mount(mock);
    shadow.ensure_dir(ROOT_INO, true).unwrap();
    let file = shadow.db().file_by_name(ROOT_INO, "f").unwrap().unwrap();
    let first = shadow
        .db()
        .fuse_for(file.ino, file.version, file.kind)
        .unwrap();
    let again = shadow
        .db()
        .fuse_for(file.ino, file.version, file.kind)
        .unwrap();
    assert_eq!(first, again);
    let other = shadow
        .db()
        .fuse_for(file.ino, file.version + 1, file.kind)
        .unwrap();
    assert_ne!(first, other);

    assert_eq!(
        shadow.db().add_open_ref(file.ino, file.version, 1).unwrap(),
        1
    );
    assert_eq!(
        shadow.db().add_open_ref(file.ino, file.version, 1).unwrap(),
        2
    );
    assert_eq!(
        shadow
            .db()
            .add_open_ref(file.ino, file.version, -2)
            .unwrap(),
        0
    );
}

#[test]
fn shadow_layout_and_base_snapshot_round_trip() {
    let mock = MockRemote::new();
    mock.put_file(ROOT_INO, "a", [0x61; 16], b"a", 0o644);
    let (_dir, shadow) = mount(mock);
    shadow.ensure_dir(ROOT_INO, true).unwrap();
    let base_entries = shadow.db().base_manifest(ROOT_INO).unwrap();
    assert!(base_entries.iter().any(|entry| entry.name == "a"));
    let manifest = crate::mmap::manifest::Manifest::from_base_entries(base_entries).unwrap();
    assert_eq!(manifest.len(), 1);
    let sha = manifest.hash();
    assert_ne!(sha, [0; 32]);
}

#[test]
fn relative_and_reserved_names_are_rejected() {
    let (_dir, shadow) = mount(MockRemote::new());
    assert!(shadow.lookup(1, "a/b").is_err());
    assert!(shadow.lookup(1, ".").is_err());
    assert!(shadow.lookup(1, "..").is_err());
}

#[test]
fn lock_table_and_flock_are_local() {
    let (_dir, shadow) = mount(MockRemote::new());
    shadow.ensure_dir(ROOT_INO, true).unwrap();
    assert!(shadow.locks.is_empty());
    let ino = [0x71; 16];
    shadow
        .locks
        .setlk(ino, 1, 0, 9, libc::F_WRLCK, 1, false)
        .unwrap();
    assert!(
        shadow
            .locks
            .getlk(ino, 2, 0, 9, libc::F_RDLCK)
            .unwrap()
            .is_some()
    );
    shadow.locks.release_owner(ino, 1);
    assert!(shadow.locks.is_empty());
}

#[test]
fn signature_from_mock_is_a_usable_delta_basis() {
    let mock = MockRemote::new();
    mock.put_file(ROOT_INO, "f", [0x81; 16], b"abcdefgh", 0o644);
    let (_dir, shadow) = mount(mock);
    shadow.ensure_dir(ROOT_INO, true).unwrap();
    let file = shadow.db().file_by_name(ROOT_INO, "f").unwrap().unwrap();
    let signature: Signature = sign(Cursor::new(b"abcdefgh"), block_size_for(8)).unwrap();
    assert_eq!(signature.basis_len(), 8);
    assert_eq!(file.size, 8);
    let _: Hash = file.file_root;
}

#[test]
fn instruction_remap_keeps_every_record_on_the_manifest_index() {
    let instructions = vec![
        Instruction::Literal {
            file: 0,
            bytes: b"x".to_vec(),
        },
        Instruction::EndFile { file: 0 },
        Instruction::EndBatch,
    ];
    let remapped = super::upload::remap(instructions, 7);
    assert_eq!(remapped[0].file(), Some(7));
    assert_eq!(remapped[1].file(), Some(7));
    assert_eq!(remapped[2].file(), None);
}

#[test]
fn decode_roundtrip_of_upload_instructions() {
    let instructions = vec![
        Instruction::Unchanged {
            file: 2,
            content_hash: [0x33; 32],
        },
        Instruction::EndFile { file: 2 },
        Instruction::EndBatch,
    ];
    let mut bytes = Vec::new();
    crate::mmap::rsync::encode_to(&instructions, &mut bytes).unwrap();
    assert_eq!(decode_from(Cursor::new(bytes)).unwrap(), instructions);
}

#[test]
fn shadow_error_maps_conflicts_to_eagain() {
    assert_eq!(
        ShadowError::Remote(RemoteError::LockExpired).errno(),
        libc::EAGAIN
    );
    assert_eq!(
        ShadowError::Remote(RemoteError::BaseChanged {
            current: MmBase::new(1, crate::mmap::types::DirSeq::new(1), [0; 32]),
            snapshot_seq: MmSeq::new(1),
        })
        .errno(),
        libc::EAGAIN
    );
    assert_eq!(ShadowError::NotFound.errno(), libc::ENOENT);
}

/// Ensure the public `FileRecord` conversion used by base snapshots is
/// reachable from the test module.
#[test]
fn file_record_manifest_entry_is_keep() {
    let record = FileRecord {
        ino: [9; 16],
        dir_ino: ROOT_INO,
        name: "x".to_owned(),
        kind: EntryKind::File,
        attrs: root_attr(),
        size: 0,
        file_root: super::content::ContentHashes::empty().file_root,
        content_hash: Some(super::content::ContentHashes::empty().content_hash),
        target: None,
        version: 1,
        deleted: false,
        created_at_ms: 0,
        updated_at_ms: 0,
    };
    let entry = record.manifest_entry(EntryOp::Keep);
    assert_eq!(entry.name, "x");
    assert_eq!(entry.kind, EntryKind::File);
}

#[test]
fn mock_body_and_base_are_visible_to_tests() {
    let mock = MockRemote::new();
    mock.put_file(ROOT_INO, "x", [0xa1; 16], b"v", 0o644);
    assert_eq!(mock.body(ROOT_INO, "x").unwrap(), b"v");
    let base = mock.base(ROOT_INO);
    assert_eq!(base.epoch, 1);
}

// ---------------------------------------------------------------------------
// Restart recovery
// ---------------------------------------------------------------------------

fn open_shadow(root: &std::path::Path, mock: &Arc<MockRemote>) -> Shadow {
    let mut config = ShadowConfig::new(root, NS);
    config.revalidate_ttl = Duration::ZERO;
    let remote: Arc<dyn MmRemote> = mock.clone();
    Shadow::open(config, remote).unwrap()
}

/// Mount one directory and write `f` without uploading it.
fn dirty_root(mock: &Arc<MockRemote>, root: &std::path::Path) -> (Shadow, Ino, u64, u64) {
    let shadow = open_shadow(root, mock);
    shadow.ensure_dir(ROOT_INO, true).unwrap();
    let (attr, handle) = shadow
        .create(1, "f", 0o100644, 0, 1000, 1000, true)
        .unwrap();
    shadow.write(attr.fuse_ino, handle.id, 0, b"hello").unwrap();
    let dir = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
    let file = shadow.db().file_by_name(ROOT_INO, "f").unwrap().unwrap();
    (shadow, file.ino, file.version, dir.dirty_gen)
}

fn persist_upload(shadow: &Shadow, batch_id: BatchId, snapshot_gen: u64) {
    shadow
        .db()
        .set_snapshot_gen(ROOT_INO, snapshot_gen)
        .unwrap();
    shadow
        .db()
        .set_upload_phase(ROOT_INO, UploadPhase::Uploading, Some(batch_id), None)
        .unwrap();
}

fn begin_upload(mock: &MockRemote, batch_id: BatchId) {
    mock.upload(&UploadRequest::Begin(UploadBegin {
        batch_id,
        dir_path: "/".to_owned(),
        dir_ino: ROOT_INO,
        base: mock.base(ROOT_INO),
        manifest: Vec::new(),
    }))
    .unwrap();
}

/// Rewind the local publish of a committed batch: the server keeps the
/// commit, the mount behaves as if it died before recording it.
fn rewind_publish(
    shadow: &Shadow,
    before: &ShadowDir,
    file_ino: Ino,
    file_version: u64,
    batch_id: BatchId,
    snapshot_gen: u64,
) {
    shadow
        .db()
        .write(|tx| {
            tx.conn().execute(
                "UPDATE mm_dirs
                 SET base_epoch = ?1, base_seq = ?2, dir_version = ?3, phase = 'ready'
                 WHERE namespace = ?4 AND ino = ?5",
                rusqlite::params![
                    i64::try_from(before.record.base.epoch).unwrap(),
                    i64::try_from(before.record.base.dir_seq.get()).unwrap(),
                    before.record.base.dir_version.as_slice(),
                    NS,
                    ROOT_INO.as_slice(),
                ],
            )?;
            tx.conn().execute(
                "DELETE FROM mm_dir_versions WHERE namespace = ?1 AND dir_ino = ?2",
                rusqlite::params![NS, ROOT_INO.as_slice()],
            )?;
            tx.conn().execute(
                "UPDATE shadow_versions
                 SET dirty_gen = ?1, state = 'dirty', synced_size = 0, synced_mtime_ns = 0
                 WHERE ino = ?2 AND version = ?3",
                rusqlite::params![
                    i64::try_from(snapshot_gen).unwrap(),
                    file_ino.as_slice(),
                    i64::try_from(file_version).unwrap(),
                ],
            )?;
            tx.conn().execute(
                "UPDATE shadow_dirs
                 SET dirty_gen = ?1, uploaded_gen = ?2, upload_state = 'uploading',
                     batch_id = ?3, lock_id = NULL, snapshot_gen = ?4,
                     snapshot_seq = ?5, valid_until_ms = 0
                 WHERE dir_ino = ?6",
                rusqlite::params![
                    i64::try_from(before.dirty_gen).unwrap(),
                    i64::try_from(before.uploaded_gen).unwrap(),
                    batch_id.as_bytes().as_slice(),
                    i64::try_from(snapshot_gen).unwrap(),
                    i64::try_from(before.snapshot_seq.get()).unwrap(),
                    ROOT_INO.as_slice(),
                ],
            )?;
            Ok(())
        })
        .unwrap();
}

#[test]
fn restart_adopts_committed_batch_without_uploading_it_again() {
    let mock = MockRemote::new();
    let root = tempfile::tempdir().unwrap();
    let (shadow, file_ino, file_version, snapshot_gen) = dirty_root(&mock, root.path());
    let before = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
    let fuse_ino = shadow.lookup(1, "f").unwrap().fuse_ino;
    shadow.fsync(fuse_ino, None).unwrap();
    assert_eq!(mock.commits().len(), 1);
    let batch_id = mock.commits()[0].batch_id;
    let committed_base = mock.base(ROOT_INO);
    let committed_seq = mock.snapshot_seq();
    assert_eq!(
        shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap().batch_id,
        None
    );

    rewind_publish(
        &shadow,
        &before,
        file_ino,
        file_version,
        batch_id,
        snapshot_gen,
    );
    drop(shadow);

    let shadow = open_shadow(root.path(), &mock);
    let dir = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
    assert_eq!(dir.batch_id, None);
    assert_eq!(dir.upload_state, UploadPhase::Idle);
    assert!(dir.clean());
    assert_eq!(dir.record.base, committed_base);
    assert_eq!(dir.snapshot_seq, committed_seq);
    assert_eq!(dir.uploaded_gen, snapshot_gen);
    assert_eq!(dir.snapshot_gen, 0);
    let version = shadow
        .db()
        .shadow_version(file_ino, file_version)
        .unwrap()
        .unwrap();
    assert_eq!(version.dirty_gen, 0);
    assert_eq!(version.state, VersionState::Clean);
    assert_eq!(mock.commits().len(), 1, "recovery must not upload");
    assert_eq!(mock.batch_count(), 1, "recovery must not begin a batch");

    // Adoption does not rotate the file version: an old descriptor or
    // mapping keeps its object.
    let file = shadow.db().file_by_name(ROOT_INO, "f").unwrap().unwrap();
    assert_eq!((file.ino, file.version), (file_ino, file_version));

    // Nothing left to flush, and a second restart asks the server nothing.
    let statuses = mock.statuses();
    shadow.fsync(fuse_ino, None).unwrap();
    assert_eq!(mock.commits().len(), 1);
    drop(shadow);
    let shadow = open_shadow(root.path(), &mock);
    assert_eq!(mock.statuses(), statuses);
    assert_eq!(
        shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap().batch_id,
        None
    );
}

#[test]
fn restart_keeps_an_open_batch_for_the_next_fsync() {
    let mock = MockRemote::new();
    let root = tempfile::tempdir().unwrap();
    let (shadow, _file_ino, _file_version, snapshot_gen) = dirty_root(&mock, root.path());
    let batch_id = BatchId::from_bytes([0x77; 16]);
    begin_upload(&mock, batch_id);
    persist_upload(&shadow, batch_id, snapshot_gen);
    let fuse_ino = shadow.lookup(1, "f").unwrap().fuse_ino;
    drop(shadow);

    let shadow = open_shadow(root.path(), &mock);
    let dir = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
    assert_eq!(dir.batch_id, Some(batch_id));
    assert_eq!(dir.upload_state, UploadPhase::Dirty);
    assert!(!dir.clean());
    assert_eq!(mock.batch_state(batch_id), Some(BatchState::Open));
    assert!(mock.commits().is_empty(), "an open batch is not resent");

    // The next fsync starts a new batch and leaves the old one alone.
    shadow.fsync(fuse_ino, None).unwrap();
    assert_eq!(mock.commits().len(), 1);
    assert_ne!(mock.commits()[0].batch_id, batch_id);
    assert_eq!(mock.batch_state(batch_id), Some(BatchState::Open));
    assert_eq!(
        shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap().batch_id,
        None
    );
}

#[test]
fn restart_clears_an_aborted_batch_and_keeps_dirty() {
    let mock = MockRemote::new();
    let root = tempfile::tempdir().unwrap();
    let (shadow, file_ino, file_version, snapshot_gen) = dirty_root(&mock, root.path());
    let batch_id = BatchId::from_bytes([0x78; 16]);
    begin_upload(&mock, batch_id);
    mock.upload(&UploadRequest::Abort(UploadAbort {
        batch_id,
        lock_id: LockId::from_bytes([0x11; 16]),
    }))
    .unwrap();
    persist_upload(&shadow, batch_id, snapshot_gen);
    drop(shadow);

    let shadow = open_shadow(root.path(), &mock);
    let dir = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
    assert_eq!(dir.batch_id, None);
    assert_eq!(dir.upload_state, UploadPhase::Dirty);
    assert_eq!(dir.snapshot_gen, 0);
    assert!(!dir.clean());
    let version = shadow
        .db()
        .shadow_version(file_ino, file_version)
        .unwrap()
        .unwrap();
    assert_eq!(version.dirty_gen, snapshot_gen);
    assert_eq!(version.state, VersionState::Dirty);
    assert!(mock.commits().is_empty());
    assert_eq!(mock.batch_count(), 1, "an aborted batch is not resent");
}

#[test]
fn restart_clears_an_unknown_batch_and_keeps_dirty() {
    let mock = MockRemote::new();
    let root = tempfile::tempdir().unwrap();
    let (shadow, file_ino, file_version, snapshot_gen) = dirty_root(&mock, root.path());
    let batch_id = BatchId::from_bytes([0x79; 16]);
    persist_upload(&shadow, batch_id, snapshot_gen);
    drop(shadow);

    let shadow = open_shadow(root.path(), &mock);
    let dir = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
    assert_eq!(dir.batch_id, None);
    assert_eq!(dir.upload_state, UploadPhase::Dirty);
    assert!(!dir.clean());
    let version = shadow
        .db()
        .shadow_version(file_ino, file_version)
        .unwrap()
        .unwrap();
    assert_eq!(version.dirty_gen, snapshot_gen);
    assert_eq!(version.state, VersionState::Dirty);
    assert!(mock.commits().is_empty());
    assert_eq!(mock.batch_count(), 0, "an unknown batch is not begun");
}

#[test]
fn restart_keeps_state_when_batch_status_is_unreachable() {
    let mock = MockRemote::new();
    let root = tempfile::tempdir().unwrap();
    let (shadow, _file_ino, _file_version, snapshot_gen) = dirty_root(&mock, root.path());
    let batch_id = BatchId::from_bytes([0x7a; 16]);
    begin_upload(&mock, batch_id);
    persist_upload(&shadow, batch_id, snapshot_gen);
    let fuse_ino = shadow.lookup(1, "f").unwrap().fuse_ino;
    mock.set_failure(FailPoint::BatchStatus, RemoteError::Io("down".to_owned()));
    drop(shadow);

    // A transport failure never blocks the mount.
    let shadow = open_shadow(root.path(), &mock);
    let dir = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
    assert_eq!(dir.batch_id, Some(batch_id));
    assert!(!dir.clean());

    // Authentication failure keeps the same state for the next fsync.
    mock.set_failure(FailPoint::BatchStatus, RemoteError::Unauthenticated);
    let error = shadow.fsync(fuse_ino, None).unwrap_err();
    assert!(matches!(
        error,
        ShadowError::Remote(RemoteError::Unauthenticated)
    ));
    let dir = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
    assert_eq!(dir.batch_id, Some(batch_id));
    assert!(!dir.clean());
    assert!(mock.commits().is_empty());
    assert_eq!(mock.batch_count(), 1, "an unreachable batch is not resent");

    // Once the server answers, the next fsync starts a new batch.
    shadow.fsync(fuse_ino, None).unwrap();
    assert_eq!(mock.commits().len(), 1);
    assert_ne!(mock.commits()[0].batch_id, batch_id);
    assert_eq!(mock.batch_count(), 2);
}

#[test]
fn restart_adoption_keeps_a_newer_dirty_generation() {
    let mock = MockRemote::new();
    let root = tempfile::tempdir().unwrap();
    let (shadow, file_ino, file_version, snapshot_gen) = dirty_root(&mock, root.path());
    let before = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
    let fuse_ino = shadow.lookup(1, "f").unwrap().fuse_ino;
    shadow.fsync(fuse_ino, None).unwrap();
    let batch_id = mock.commits()[0].batch_id;
    let committed_base = mock.base(ROOT_INO);
    let committed_seq = mock.snapshot_seq();
    rewind_publish(
        &shadow,
        &before,
        file_ino,
        file_version,
        batch_id,
        snapshot_gen,
    );
    // A write that arrived after the snapshot has a newer generation.
    shadow
        .db()
        .write(|tx| {
            tx.conn().execute(
                "UPDATE shadow_dirs SET dirty_gen = ?1 WHERE dir_ino = ?2",
                rusqlite::params![
                    i64::try_from(snapshot_gen + 1).unwrap(),
                    ROOT_INO.as_slice()
                ],
            )?;
            tx.conn().execute(
                "UPDATE shadow_versions SET dirty_gen = ?1 WHERE ino = ?2 AND version = ?3",
                rusqlite::params![
                    i64::try_from(snapshot_gen + 1).unwrap(),
                    file_ino.as_slice(),
                    i64::try_from(file_version).unwrap(),
                ],
            )?;
            Ok(())
        })
        .unwrap();
    drop(shadow);

    let shadow = open_shadow(root.path(), &mock);
    let dir = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
    assert_eq!(dir.record.base, committed_base);
    assert_eq!(dir.snapshot_seq, committed_seq);
    assert_eq!(dir.uploaded_gen, snapshot_gen);
    assert!(!dir.clean(), "a write after the snapshot stays dirty");
    let version = shadow
        .db()
        .shadow_version(file_ino, file_version)
        .unwrap()
        .unwrap();
    assert_eq!(version.dirty_gen, snapshot_gen + 1);
    assert_eq!(version.state, VersionState::Dirty);

    // The next fsync uploads the later content.
    let handle = shadow.open_file(fuse_ino, true).unwrap();
    shadow.write(fuse_ino, handle.id, 0, b"world").unwrap();
    shadow.fsync(fuse_ino, Some(handle.id)).unwrap();
    assert_eq!(mock.commits().len(), 2);
    let dir = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
    assert_eq!(dir.batch_id, None);
    assert!(dir.clean());
}

#[test]
fn publish_committed_never_rolls_back_a_newer_checkout() {
    let mock = MockRemote::new();
    let root = tempfile::tempdir().unwrap();
    let (shadow, _file_ino, _file_version, _snapshot_gen) = dirty_root(&mock, root.path());
    let dir = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
    let older = MmBase::new(
        dir.record.base.epoch,
        crate::mmap::types::DirSeq::new(dir.record.base.dir_seq.get() + 1),
        [0x5a; 32],
    );
    let adopted = shadow
        .db()
        .publish_committed(ROOT_INO, older, dir.snapshot_seq, dir.dirty_gen, 0, None)
        .unwrap();
    assert!(!adopted, "an older snapshot must not replace a newer base");
    let after = shadow.db().shadow_dir(ROOT_INO).unwrap().unwrap();
    assert_eq!(after.record.base, dir.record.base);
    assert!(!after.clean(), "dirty generations stay for the next fsync");
}

#[test]
fn schema_migration_adds_snapshot_gen_to_an_old_shadow_db() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE shadow_dirs (
           dir_ino BLOB PRIMARY KEY NOT NULL,
           upload_state TEXT NOT NULL DEFAULT 'idle'
         ) STRICT, WITHOUT ROWID;",
    )
    .unwrap();
    super::db::migrate(&conn).unwrap();
    super::db::migrate(&conn).unwrap();
    let mut stmt = conn.prepare("PRAGMA table_info(shadow_dirs)").unwrap();
    let names: Vec<String> = stmt
        .query_map([], |row| row.get(1))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(names.iter().any(|name| name == "snapshot_gen"));
}
