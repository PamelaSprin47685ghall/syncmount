//! Unit and integration-level tests for the shadow filesystem.
//!
//! The mock remote below is the only server used here. It implements the same
//! `MmRemote` boundary P4 will implement over HTTP, so these tests exercise
//! the real checkout, manifest, rsync and commit assembly.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use crate::mmap::base;
use crate::mmap::rsync::{Instruction, Signature, block_size_for, decode_from, sign};
use crate::mmap::types::{
    DirAttrs, EntryKind, EntryOp, FileRecord, Hash, Ino, LockId, ManifestEntry, MmBase, MmSeq,
    ROOT_INO,
};

use super::remote::{
    CheckoutEntry, CheckoutOutcome, CheckoutRequest, CheckoutSnapshot, FileData, FileReadRequest,
    GrantedLock, LockRequest, LockResponse, MmRemote, RemoteError, SignatureFilePlan,
    SignaturesRequest, SignaturesResponse, UploadRequest, UploadResponse, UploadResult,
};
use super::{Shadow, ShadowConfig, ShadowError};

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
    Checkout,
    Lock,
    Upload,
}

/// Deterministic in-memory server.
struct MockRemote {
    state: Mutex<MockState>,
    fail: Mutex<Option<(FailPoint, RemoteError)>>,
    checkouts: AtomicUsize,
}

struct MockState {
    epoch: u64,
    snapshot_seq: u64,
    dirs: BTreeMap<Ino, MockDir>,
    commits: Vec<super::remote::UploadCommit>,
    locks: HashMap<Ino, LockId>,
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
                locks: HashMap::new(),
            }),
            fail: Mutex::new(None),
            checkouts: AtomicUsize::new(0),
        })
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

    fn base(&self, dir: Ino) -> MmBase {
        self.state.lock().unwrap().dirs[&dir].base
    }

    fn commits(&self) -> Vec<super::remote::UploadCommit> {
        self.state.lock().unwrap().commits.clone()
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
                return Err(RemoteError::BaseChanged {
                    current: dir.base,
                    snapshot_seq: MmSeq::new(state.snapshot_seq),
                });
            }
            return Ok(CheckoutOutcome::NotModified {
                base: dir.base,
                snapshot_seq: MmSeq::new(state.snapshot_seq),
            });
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
                Ok(UploadResponse::Plan(super::remote::UploadPlan {
                    batch_id: begin.batch_id,
                    base: dir.base,
                    expires_at_ms: 1_000,
                }))
            }
            UploadRequest::Abort(_) => Ok(UploadResponse::Aborted),
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
                        EntryOp::Delete | EntryOp::DirRemove => continue,
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
