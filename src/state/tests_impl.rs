//! Unit tests for the pure namespace state machine.
//!
//! These tests use only the public surface plus [`State::commit`], so they are
//! also a check that the `Change` list is sufficient to reproduce the plan.

use super::*;

fn h(seed: u8) -> Hash {
    [seed; 32]
}

fn full(seed: u8) -> Chunk {
    Chunk::new(h(seed), CHUNK_BYTES as u32)
}

fn part(seed: u8, len: u32) -> Chunk {
    Chunk::new(h(seed), len)
}

fn apply_ok(state: &mut State, op: &Op) {
    if let Err(reject) = state.apply(op) {
        panic!("{} was rejected: {reject}", op.name());
    }
}

fn apply_err(state: &mut State, op: &Op, errno: Errno) {
    match state.apply(op) {
        Ok(()) => panic!("{} unexpectedly applied", op.name()),
        Err(reject) => assert_eq!(reject.errno, errno, "{}: {reject}", op.name()),
    }
}

fn plan_ok(state: &State, op: &Op) -> Vec<Change> {
    match state.plan(op) {
        Verdict::Apply(changes) => changes,
        Verdict::Reject(reject) => panic!("{} was rejected: {reject}", op.name()),
    }
}

fn plan_err(state: &State, op: &Op, errno: Errno) -> Reject {
    match state.plan(op) {
        Verdict::Reject(reject) => {
            assert_eq!(reject.errno, errno, "{}: {reject}", op.name());
            reject
        }
        Verdict::Apply(_) => panic!("{} unexpectedly applied", op.name()),
    }
}

fn create_file(state: &mut State, path: &str, ino: Ino) {
    apply_ok(
        state,
        &Op::CreateFile {
            path: path.as_bytes().to_vec(),
            ino,
            mode: 0o644,
            uid: 1,
            gid: 2,
            mtime_ns: 10,
        },
    );
}

fn create_dir(state: &mut State, path: &str, ino: Ino) {
    apply_ok(
        state,
        &Op::CreateDir {
            path: path.as_bytes().to_vec(),
            ino,
            mode: 0o755,
            uid: 1,
            gid: 2,
            mtime_ns: 10,
        },
    );
}

fn write_file(state: &mut State, path: &str, chunks: Vec<Chunk>) {
    apply_ok(
        state,
        &Op::Write {
            path: path.as_bytes().to_vec(),
            chunks,
            mtime_ns: 20,
        },
    );
}

fn rename(state: &mut State, from: &str, to: &str) {
    apply_ok(
        state,
        &Op::Rename {
            from: from.as_bytes().to_vec(),
            to: to.as_bytes().to_vec(),
            mtime_ns: 30,
        },
    );
}

fn nlink(state: &State, ino: Ino) -> u32 {
    match state.object(ino) {
        Some(object) => object.nlink,
        None => panic!("inode {ino} is missing"),
    }
}

fn mtime(state: &State, ino: Ino) -> u64 {
    match state.object(ino) {
        Some(object) => object.mtime_ns,
        None => panic!("inode {ino} is missing"),
    }
}

// ---------------------------------------------------------------------------
// Root, creation and path rules
// ---------------------------------------------------------------------------

#[test]
fn u_state_root_initial() {
    let state = State::new();
    assert_eq!(state.check_invariants(), Ok(()));
    let root = state.object(ROOT);
    assert!(root.is_some());
    if let Some(root) = root {
        assert_eq!(root.kind, Kind::Dir);
        assert_eq!(root.mode, 0o755);
        assert_eq!(root.nlink, 2);
        assert_eq!(root.size, 0);
        assert_eq!(root.file_root, dir_root());
        assert!(root.target.is_none());
    }
    assert_eq!(state.resolve(b"/"), Ok(ROOT));
    assert!(state.is_empty());
    assert_eq!(state.len(), 1);
    assert_eq!(state.digest(), State::new().digest());
}

#[test]
fn u_state_create_file_applies_and_masks_mode() {
    let mut state = State::new();
    let op = Op::CreateFile {
        path: b"/f".to_vec(),
        ino: 7,
        mode: 0o107777,
        uid: 3,
        gid: 4,
        mtime_ns: 99,
    };
    let changes = plan_ok(&state, &op);
    assert!(matches!(changes.first(), Some(Change::InsertObject(_))));
    assert!(matches!(changes.get(1), Some(Change::InsertName { .. })));
    assert!(matches!(changes.get(2), Some(Change::UpdateObject { .. })));
    state.commit(changes);
    assert_eq!(state.check_invariants(), Ok(()));

    let object = state.object(7);
    assert!(object.is_some());
    if let Some(object) = object {
        assert_eq!(object.kind, Kind::File);
        assert_eq!(object.mode, 0o7777);
        assert_eq!(object.uid, 3);
        assert_eq!(object.gid, 4);
        assert_eq!(object.mtime_ns, 99);
        assert_eq!(object.size, 0);
        assert_eq!(object.file_root, empty_file_root());
        assert_eq!(object.nlink, 1);
        assert!(object.target.is_none());
    }
    assert_eq!(state.lookup(ROOT, b"f"), Some(7));
    assert_eq!(nlink(&state, ROOT), 2);
    assert_eq!(mtime(&state, ROOT), 99);
}

#[test]
fn u_state_create_file_rejects() {
    let mut state = State::new();
    create_file(&mut state, "/f", 7);
    apply_err(
        &mut state,
        &Op::CreateFile {
            path: b"/f".to_vec(),
            ino: 8,
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime_ns: 0,
        },
        Errno::EEXIST,
    );
    apply_err(
        &mut state,
        &Op::CreateFile {
            path: b"/missing/f".to_vec(),
            ino: 8,
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime_ns: 0,
        },
        Errno::ENOENT,
    );
    apply_err(
        &mut state,
        &Op::CreateFile {
            path: b"/f/child".to_vec(),
            ino: 8,
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime_ns: 0,
        },
        Errno::ENOTDIR,
    );
    apply_err(
        &mut state,
        &Op::CreateFile {
            path: b"/".to_vec(),
            ino: 8,
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime_ns: 0,
        },
        Errno::EEXIST,
    );
    apply_err(
        &mut state,
        &Op::CreateFile {
            path: b"/g".to_vec(),
            ino: 7,
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime_ns: 0,
        },
        Errno::EEXIST,
    );
    assert_eq!(state.check_invariants(), Ok(()));
}

#[test]
fn u_state_create_dir_updates_parent_nlink() {
    let mut state = State::new();
    create_dir(&mut state, "/d", 7);
    assert_eq!(nlink(&state, 7), 2);
    assert_eq!(nlink(&state, ROOT), 3);
    create_dir(&mut state, "/d/e", 8);
    assert_eq!(nlink(&state, 7), 3);
    assert_eq!(nlink(&state, ROOT), 3);
    assert_eq!(state.check_invariants(), Ok(()));
    apply_err(
        &mut state,
        &Op::CreateDir {
            path: b"/d".to_vec(),
            ino: 9,
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime_ns: 0,
        },
        Errno::EEXIST,
    );
    apply_err(
        &mut state,
        &Op::CreateDir {
            path: b"/".to_vec(),
            ino: 9,
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime_ns: 0,
        },
        Errno::EEXIST,
    );
}

#[test]
fn u_state_symlink_rules() {
    let mut state = State::new();
    let op = Op::Symlink {
        path: b"/s".to_vec(),
        ino: 9,
        target: b"../target".to_vec(),
        uid: 1,
        gid: 2,
        mtime_ns: 5,
    };
    apply_ok(&mut state, &op);
    assert_eq!(state.check_invariants(), Ok(()));
    let object = state.object(9);
    assert!(object.is_some());
    if let Some(object) = object {
        assert_eq!(object.kind, Kind::Symlink);
        assert_eq!(object.mode, 0o777);
        assert_eq!(object.size, 9);
        assert_eq!(object.file_root, symlink_root(b"../target"));
        assert_eq!(object.target.as_deref(), Some(b"../target".as_slice()));
        assert_eq!(object.nlink, 1);
    }
    apply_err(
        &mut state,
        &Op::Symlink {
            path: b"/empty".to_vec(),
            ino: 10,
            target: Vec::new(),
            uid: 0,
            gid: 0,
            mtime_ns: 0,
        },
        Errno::EINVAL,
    );
    apply_err(
        &mut state,
        &Op::Symlink {
            path: b"/nul".to_vec(),
            ino: 10,
            target: b"a\0b".to_vec(),
            uid: 0,
            gid: 0,
            mtime_ns: 0,
        },
        Errno::EINVAL,
    );
    apply_err(
        &mut state,
        &Op::Symlink {
            path: b"/s".to_vec(),
            ino: 10,
            target: b"x".to_vec(),
            uid: 0,
            gid: 0,
            mtime_ns: 0,
        },
        Errno::EEXIST,
    );
}

// ---------------------------------------------------------------------------
// Write / truncate / setattr
// ---------------------------------------------------------------------------

#[test]
fn u_state_write_updates_chunks_size_and_root() {
    let mut state = State::new();
    create_file(&mut state, "/f", 7);
    let chunks = vec![full(1), part(2, 123)];
    let expected_size = CHUNK_BYTES + 123;
    let expected_root = file_root(&chunks);
    let op = Op::Write {
        path: b"/f".to_vec(),
        chunks: chunks.clone(),
        mtime_ns: 44,
    };
    let changes = plan_ok(&state, &op);
    assert!(matches!(changes.first(), Some(Change::UpdateChunks { .. })));
    state.commit(changes);
    assert_eq!(state.check_invariants(), Ok(()));
    let object = state.object(7);
    assert!(object.is_some());
    if let Some(object) = object {
        assert_eq!(object.size, expected_size);
        assert_eq!(object.file_root, expected_root);
        assert_eq!(object.mtime_ns, 44);
    }
    assert_eq!(state.chunks(7), chunks.as_slice());
}

#[test]
fn u_state_write_empty_file() {
    let mut state = State::new();
    create_file(&mut state, "/f", 7);
    write_file(&mut state, "/f", vec![]);
    assert_eq!(state.object(7).map(|object| object.size), Some(0));
    assert_eq!(
        state.object(7).map(|object| object.file_root),
        Some(empty_file_root())
    );
    assert_eq!(state.check_invariants(), Ok(()));
}

#[test]
fn u_state_write_rejects_bad_targets_and_chunks() {
    let mut state = State::new();
    create_file(&mut state, "/f", 7);
    create_dir(&mut state, "/d", 8);
    apply_ok(
        &mut state,
        &Op::Symlink {
            path: b"/s".to_vec(),
            ino: 9,
            target: b"x".to_vec(),
            uid: 0,
            gid: 0,
            mtime_ns: 0,
        },
    );
    apply_err(
        &mut state,
        &Op::Write {
            path: b"/d".to_vec(),
            chunks: vec![],
            mtime_ns: 0,
        },
        Errno::EISDIR,
    );
    apply_err(
        &mut state,
        &Op::Write {
            path: b"/s".to_vec(),
            chunks: vec![],
            mtime_ns: 0,
        },
        Errno::EINVAL,
    );
    apply_err(
        &mut state,
        &Op::Write {
            path: b"/missing".to_vec(),
            chunks: vec![],
            mtime_ns: 0,
        },
        Errno::ENOENT,
    );
    for chunks in [
        vec![part(1, 0)],
        vec![part(1, 1), part(2, 1)],
        vec![part(1, (CHUNK_BYTES + 1) as u32)],
    ] {
        apply_err(
            &mut state,
            &Op::Write {
                path: b"/f".to_vec(),
                chunks,
                mtime_ns: 0,
            },
            Errno::EINVAL,
        );
    }
    assert_eq!(state.check_invariants(), Ok(()));
}

#[test]
fn u_state_truncate_requires_matching_size() {
    let mut state = State::new();
    create_file(&mut state, "/f", 7);
    write_file(&mut state, "/f", vec![full(1), full(2)]);
    let op = Op::Truncate {
        path: b"/f".to_vec(),
        size: CHUNK_BYTES,
        chunks: vec![full(1)],
        mtime_ns: 55,
    };
    apply_ok(&mut state, &op);
    assert_eq!(state.object(7).map(|object| object.size), Some(CHUNK_BYTES));
    assert_eq!(state.object(7).map(|object| object.mtime_ns), Some(55));
    assert_eq!(state.check_invariants(), Ok(()));

    apply_err(
        &mut state,
        &Op::Truncate {
            path: b"/f".to_vec(),
            size: 1,
            chunks: vec![full(1)],
            mtime_ns: 0,
        },
        Errno::EINVAL,
    );
    apply_ok(
        &mut state,
        &Op::Truncate {
            path: b"/f".to_vec(),
            size: 0,
            chunks: vec![],
            mtime_ns: 0,
        },
    );
    assert_eq!(state.object(7).map(|object| object.size), Some(0));
    assert_eq!(state.check_invariants(), Ok(()));
}

#[test]
fn u_state_setattr_is_partial_and_masks_mode() {
    let mut state = State::new();
    create_file(&mut state, "/f", 7);
    let before = state.object(7).cloned();
    let changes = plan_ok(
        &state,
        &Op::SetAttr {
            path: b"/f".to_vec(),
            attrs: Attrs {
                mode: Some(0o107600),
                ..Attrs::default()
            },
            size: None,
            chunks: Vec::new(),
        },
    );
    assert_eq!(changes.len(), 1);
    state.commit(changes);
    assert_eq!(state.object(7).map(|object| object.mode), Some(0o7600));
    if let (Some(before), Some(after)) = (before.as_ref(), state.object(7)) {
        assert_eq!(before.uid, after.uid);
        assert_eq!(before.gid, after.gid);
        assert_eq!(before.mtime_ns, after.mtime_ns);
    }
    let noop = plan_ok(
        &state,
        &Op::SetAttr {
            path: b"/f".to_vec(),
            attrs: Attrs::default(),
            size: None,
            chunks: Vec::new(),
        },
    );
    assert!(noop.is_empty());
    apply_err(
        &mut state,
        &Op::SetAttr {
            path: b"/missing".to_vec(),
            attrs: Attrs {
                uid: Some(1),
                ..Attrs::default()
            },
            size: None,
            chunks: Vec::new(),
        },
        Errno::ENOENT,
    );
    assert_eq!(state.check_invariants(), Ok(()));
}

#[test]
fn u_state_setattr_size_and_mode_are_one_change_set() {
    let mut state = State::new();
    create_file(&mut state, "/f", 7);
    write_file(&mut state, "/f", vec![full(1), full(2)]);

    let op = Op::SetAttr {
        path: b"/f".to_vec(),
        attrs: Attrs {
            mode: Some(0o600),
            mtime_ns: Some(55),
            ..Attrs::default()
        },
        size: Some(CHUNK_BYTES),
        chunks: vec![full(1)],
    };
    let changes = plan_ok(&state, &op);
    assert!(
        matches!(changes.first(), Some(Change::UpdateChunks { .. })),
        "the size change is part of the same change list"
    );
    assert!(
        matches!(changes.get(1), Some(Change::SetAttrs { .. })),
        "the metadata change is part of the same change list"
    );
    state.commit(changes);
    let Some(object) = state.object(7) else {
        panic!("file is missing");
    };
    assert_eq!(object.size, CHUNK_BYTES);
    assert_eq!(object.mode, 0o600);
    assert_eq!(object.mtime_ns, 55);
    assert_eq!(state.check_invariants(), Ok(()));

    apply_err(
        &mut state,
        &Op::SetAttr {
            path: b"/f".to_vec(),
            attrs: Attrs::default(),
            size: Some(1),
            chunks: vec![full(1)],
        },
        Errno::EINVAL,
    );
}

// ---------------------------------------------------------------------------
// Rename
// ---------------------------------------------------------------------------

#[test]
fn u_state_rename_same_parent_file_and_dir() {
    let mut state = State::new();
    create_file(&mut state, "/f", 7);
    create_dir(&mut state, "/d", 8);
    create_dir(&mut state, "/d/sub", 9);
    let parent_mtime = mtime(&state, ROOT);
    rename(&mut state, "/f", "/g");
    assert_eq!(state.lookup(ROOT, b"f"), None);
    assert_eq!(state.lookup(ROOT, b"g"), Some(7));
    assert_eq!(nlink(&state, ROOT), 3);
    assert!(mtime(&state, ROOT) > parent_mtime);
    assert_eq!(state.check_invariants(), Ok(()));

    rename(&mut state, "/d", "/e");
    assert_eq!(state.lookup(ROOT, b"d"), None);
    assert_eq!(state.lookup(ROOT, b"e"), Some(8));
    assert_eq!(nlink(&state, ROOT), 3);
    assert_eq!(nlink(&state, 8), 3);
    assert_eq!(state.check_invariants(), Ok(()));
}

#[test]
fn u_state_rename_cross_parent_nlink_matrix() {
    let mut state = State::new();
    create_dir(&mut state, "/a", 1);
    create_dir(&mut state, "/b", 2);
    create_file(&mut state, "/a/f", 3);
    create_dir(&mut state, "/a/d", 4);
    create_dir(&mut state, "/b/e", 5);

    rename(&mut state, "/a/f", "/b/g");
    assert_eq!(nlink(&state, 1), 3);
    assert_eq!(nlink(&state, 2), 3);
    assert_eq!(state.lookup(2, b"g"), Some(3));

    rename(&mut state, "/a/d", "/b/h");
    assert_eq!(nlink(&state, 1), 2);
    assert_eq!(nlink(&state, 2), 4);
    assert_eq!(nlink(&state, 4), 2);
    assert_eq!(state.check_invariants(), Ok(()));
}

#[test]
fn u_state_rename_replaces_file() {
    let mut state = State::new();
    create_file(&mut state, "/a", 1);
    create_file(&mut state, "/b", 2);
    rename(&mut state, "/a", "/b");
    assert!(state.object(1).is_some());
    assert!(state.object(2).is_none());
    assert_eq!(state.lookup(ROOT, b"b"), Some(1));
    assert_eq!(state.check_invariants(), Ok(()));

    create_file(&mut state, "/c", 3);
    create_file(&mut state, "/d", 4);
    apply_ok(
        &mut state,
        &Op::Link {
            target: b"/c".to_vec(),
            path: b"/c2".to_vec(),
            mtime_ns: 0,
        },
    );
    assert_eq!(nlink(&state, 3), 2);
    rename(&mut state, "/c", "/d");
    assert_eq!(state.lookup(ROOT, b"d"), Some(3));
    assert_eq!(state.lookup(ROOT, b"c2"), Some(3));
    assert_eq!(nlink(&state, 3), 2);
    assert!(state.object(4).is_none());
    assert_eq!(state.check_invariants(), Ok(()));
}

#[test]
fn u_state_rename_replaces_empty_dir() {
    let mut state = State::new();
    create_dir(&mut state, "/a", 1);
    create_dir(&mut state, "/b", 2);
    create_dir(&mut state, "/a/sub", 3);
    assert_eq!(nlink(&state, ROOT), 4);
    rename(&mut state, "/a", "/b");
    assert_eq!(state.lookup(ROOT, b"b"), Some(1));
    assert!(state.object(2).is_none());
    assert_eq!(nlink(&state, ROOT), 3);
    assert_eq!(nlink(&state, 1), 3);
    assert_eq!(state.check_invariants(), Ok(()));
}

#[test]
fn u_state_rename_rejects_type_mismatch_and_nonempty() {
    let mut state = State::new();
    create_dir(&mut state, "/d", 1);
    create_file(&mut state, "/f", 2);
    create_dir(&mut state, "/d/sub", 3);
    apply_err(
        &mut state,
        &Op::Rename {
            from: b"/f".to_vec(),
            to: b"/d".to_vec(),
            mtime_ns: 0,
        },
        Errno::EISDIR,
    );
    apply_err(
        &mut state,
        &Op::Rename {
            from: b"/d".to_vec(),
            to: b"/f".to_vec(),
            mtime_ns: 0,
        },
        Errno::ENOTDIR,
    );
    create_dir(&mut state, "/e", 4);
    apply_err(
        &mut state,
        &Op::Rename {
            from: b"/e".to_vec(),
            to: b"/d".to_vec(),
            mtime_ns: 0,
        },
        Errno::ENOTEMPTY,
    );
    assert_eq!(state.check_invariants(), Ok(()));
}

#[test]
fn u_state_rename_into_own_subtree_rejects() {
    let mut state = State::new();
    create_dir(&mut state, "/a", 1);
    create_dir(&mut state, "/a/b", 2);
    apply_err(
        &mut state,
        &Op::Rename {
            from: b"/a".to_vec(),
            to: b"/a/b/a".to_vec(),
            mtime_ns: 0,
        },
        Errno::EINVAL,
    );
    assert_eq!(state.check_invariants(), Ok(()));
}

#[test]
fn u_state_rename_noops() {
    let mut state = State::new();
    create_file(&mut state, "/a", 1);
    apply_ok(
        &mut state,
        &Op::Link {
            target: b"/a".to_vec(),
            path: b"/b".to_vec(),
            mtime_ns: 0,
        },
    );
    let changes = plan_ok(
        &state,
        &Op::Rename {
            from: b"/a".to_vec(),
            to: b"/b".to_vec(),
            mtime_ns: 99,
        },
    );
    assert!(changes.is_empty());
    let changes = plan_ok(
        &state,
        &Op::Rename {
            from: b"/a".to_vec(),
            to: b"/a".to_vec(),
            mtime_ns: 99,
        },
    );
    assert!(changes.is_empty());
    assert_eq!(state.lookup(ROOT, b"a"), Some(1));
    assert_eq!(state.lookup(ROOT, b"b"), Some(1));
    assert_eq!(state.check_invariants(), Ok(()));
}

#[test]
fn u_state_rename_rejects_missing_paths_and_root() {
    let mut state = State::new();
    create_file(&mut state, "/a", 1);
    apply_err(
        &mut state,
        &Op::Rename {
            from: b"/missing".to_vec(),
            to: b"/b".to_vec(),
            mtime_ns: 0,
        },
        Errno::ENOENT,
    );
    apply_err(
        &mut state,
        &Op::Rename {
            from: b"/a".to_vec(),
            to: b"/missing/b".to_vec(),
            mtime_ns: 0,
        },
        Errno::ENOENT,
    );
    apply_err(
        &mut state,
        &Op::Rename {
            from: b"/".to_vec(),
            to: b"/b".to_vec(),
            mtime_ns: 0,
        },
        Errno::EBUSY,
    );
    apply_err(
        &mut state,
        &Op::Rename {
            from: b"/a".to_vec(),
            to: b"/".to_vec(),
            mtime_ns: 0,
        },
        Errno::EBUSY,
    );
}

// ---------------------------------------------------------------------------
// Unlink / rmdir / link
// ---------------------------------------------------------------------------

#[test]
fn u_state_unlink_removes_last_name_and_keeps_hard_links() {
    let mut state = State::new();
    create_file(&mut state, "/a", 1);
    apply_ok(
        &mut state,
        &Op::Link {
            target: b"/a".to_vec(),
            path: b"/b".to_vec(),
            mtime_ns: 0,
        },
    );
    assert_eq!(nlink(&state, 1), 2);
    apply_ok(
        &mut state,
        &Op::Unlink {
            path: b"/a".to_vec(),
            mtime_ns: 40,
        },
    );
    assert!(state.object(1).is_some());
    assert_eq!(nlink(&state, 1), 1);
    assert_eq!(state.lookup(ROOT, b"a"), None);
    assert_eq!(mtime(&state, ROOT), 40);
    apply_ok(
        &mut state,
        &Op::Unlink {
            path: b"/b".to_vec(),
            mtime_ns: 41,
        },
    );
    assert!(state.object(1).is_none());
    assert_eq!(state.check_invariants(), Ok(()));
}

#[test]
fn u_state_unlink_rejects_dirs_missing_and_root() {
    let mut state = State::new();
    create_dir(&mut state, "/d", 1);
    apply_err(
        &mut state,
        &Op::Unlink {
            path: b"/d".to_vec(),
            mtime_ns: 0,
        },
        Errno::EISDIR,
    );
    apply_err(
        &mut state,
        &Op::Unlink {
            path: b"/missing".to_vec(),
            mtime_ns: 0,
        },
        Errno::ENOENT,
    );
    apply_err(
        &mut state,
        &Op::Unlink {
            path: b"/".to_vec(),
            mtime_ns: 0,
        },
        Errno::EBUSY,
    );
}

#[test]
fn u_state_rmdir_removes_empty_dir_and_rejects_rest() {
    let mut state = State::new();
    create_dir(&mut state, "/d", 1);
    create_dir(&mut state, "/d/e", 2);
    apply_err(
        &mut state,
        &Op::Rmdir {
            path: b"/d".to_vec(),
            mtime_ns: 0,
        },
        Errno::ENOTEMPTY,
    );
    apply_ok(
        &mut state,
        &Op::Rmdir {
            path: b"/d/e".to_vec(),
            mtime_ns: 5,
        },
    );
    assert_eq!(nlink(&state, 1), 2);
    apply_ok(
        &mut state,
        &Op::Rmdir {
            path: b"/d".to_vec(),
            mtime_ns: 6,
        },
    );
    assert!(state.object(1).is_none());
    assert_eq!(nlink(&state, ROOT), 2);
    assert_eq!(state.check_invariants(), Ok(()));

    create_file(&mut state, "/f", 3);
    apply_err(
        &mut state,
        &Op::Rmdir {
            path: b"/f".to_vec(),
            mtime_ns: 0,
        },
        Errno::ENOTDIR,
    );
    apply_err(
        &mut state,
        &Op::Rmdir {
            path: b"/".to_vec(),
            mtime_ns: 0,
        },
        Errno::EBUSY,
    );
    apply_err(
        &mut state,
        &Op::Rmdir {
            path: b"/missing".to_vec(),
            mtime_ns: 0,
        },
        Errno::ENOENT,
    );
}

#[test]
fn u_state_link_updates_target_nlink_and_parent_mtime() {
    let mut state = State::new();
    create_dir(&mut state, "/d", 1);
    create_file(&mut state, "/f", 2);
    let target_mtime = mtime(&state, 2);
    apply_ok(
        &mut state,
        &Op::Link {
            target: b"/f".to_vec(),
            path: b"/d/g".to_vec(),
            mtime_ns: 77,
        },
    );
    assert_eq!(nlink(&state, 2), 2);
    assert_eq!(mtime(&state, 2), target_mtime);
    assert_eq!(mtime(&state, 1), 77);
    assert_eq!(state.lookup(1, b"g"), Some(2));
    assert_eq!(state.check_invariants(), Ok(()));

    apply_err(
        &mut state,
        &Op::Link {
            target: b"/d".to_vec(),
            path: b"/h".to_vec(),
            mtime_ns: 0,
        },
        Errno::EPERM,
    );
    apply_err(
        &mut state,
        &Op::Link {
            target: b"/f".to_vec(),
            path: b"/d/g".to_vec(),
            mtime_ns: 0,
        },
        Errno::EEXIST,
    );
    apply_err(
        &mut state,
        &Op::Link {
            target: b"/missing".to_vec(),
            path: b"/h".to_vec(),
            mtime_ns: 0,
        },
        Errno::ENOENT,
    );
    apply_err(
        &mut state,
        &Op::Link {
            target: b"/f".to_vec(),
            path: b"/".to_vec(),
            mtime_ns: 0,
        },
        Errno::EEXIST,
    );
}

// ---------------------------------------------------------------------------
// Locks
// ---------------------------------------------------------------------------

const SESSION_A: Session = [1; 16];
const SESSION_B: Session = [2; 16];

fn lock(state: &mut State, session: Session, typ: LockType, start: u64, end: u64) {
    apply_ok(
        state,
        &Op::Lock {
            path: b"/f".to_vec(),
            session,
            typ,
            start,
            end,
        },
    );
}

fn unlock(state: &mut State, session: Session, start: u64, end: u64) {
    apply_ok(
        state,
        &Op::Unlock {
            path: b"/f".to_vec(),
            session,
            start,
            end,
        },
    );
}

#[test]
fn u_state_lock_conflicts_and_sharing() {
    let mut state = State::new();
    create_file(&mut state, "/f", 1);
    lock(&mut state, SESSION_A, LockType::Read, 0, 10);
    lock(&mut state, SESSION_B, LockType::Read, 5, 15);
    assert_eq!(state.locks().count(), 2);

    apply_err(
        &mut state,
        &Op::Lock {
            path: b"/f".to_vec(),
            session: SESSION_B,
            typ: LockType::Write,
            start: 5,
            end: 15,
        },
        Errno::EAGAIN,
    );
    apply_err(
        &mut state,
        &Op::Lock {
            path: b"/f".to_vec(),
            session: SESSION_A,
            typ: LockType::Write,
            start: 5,
            end: 15,
        },
        Errno::EAGAIN,
    );
    // A non-overlapping write is allowed.
    lock(&mut state, SESSION_A, LockType::Write, 20, 30);
    assert_eq!(state.locks().count(), 3);
    assert_eq!(state.check_invariants(), Ok(()));
}

#[test]
fn u_state_lock_same_session_replaces_and_unlock_trims() {
    let mut state = State::new();
    create_file(&mut state, "/f", 1);
    lock(&mut state, SESSION_A, LockType::Write, 0, 100);
    lock(&mut state, SESSION_A, LockType::Read, 10, 20);
    // The write lock is split into [0,9] and [21,100]; the new read covers
    // [10,20].
    assert_eq!(state.locks().count(), 3);
    assert_eq!(state.check_invariants(), Ok(()));

    unlock(&mut state, SESSION_A, 5, 15);
    // [0,9] -> [0,4]; [10,20] -> [16,20]; [21,100] stays.
    assert_eq!(state.locks().count(), 3);
    let mut ranges = Vec::new();
    for (key, _) in state.locks() {
        ranges.push((key.start, key.end));
    }
    ranges.sort_unstable();
    assert_eq!(ranges, vec![(0, 4), (16, 20), (21, 100)]);
    assert_eq!(state.check_invariants(), Ok(()));

    unlock(&mut state, SESSION_A, 0, u64::MAX);
    assert_eq!(state.locks().count(), 0);
}

#[test]
fn u_state_leave_clears_only_one_session() {
    let mut state = State::new();
    create_file(&mut state, "/f", 1);
    lock(&mut state, SESSION_A, LockType::Read, 0, 10);
    lock(&mut state, SESSION_B, LockType::Read, 0, 10);
    apply_ok(&mut state, &Op::Leave { session: SESSION_A });
    assert_eq!(state.locks().count(), 1);
    apply_ok(&mut state, &Op::Leave { session: SESSION_A });
    assert_eq!(state.locks().count(), 1);
    assert_eq!(state.check_invariants(), Ok(()));
}

#[test]
fn u_state_lock_rejects_bad_paths_and_ranges() {
    let mut state = State::new();
    apply_err(
        &mut state,
        &Op::Lock {
            path: b"/missing".to_vec(),
            session: SESSION_A,
            typ: LockType::Read,
            start: 0,
            end: 0,
        },
        Errno::ENOENT,
    );
    create_file(&mut state, "/f", 1);
    apply_err(
        &mut state,
        &Op::Lock {
            path: b"/f".to_vec(),
            session: SESSION_A,
            typ: LockType::Read,
            start: 5,
            end: 4,
        },
        Errno::EINVAL,
    );
    apply_err(
        &mut state,
        &Op::Unlock {
            path: b"/f".to_vec(),
            session: SESSION_A,
            start: 5,
            end: 4,
        },
        Errno::EINVAL,
    );
    apply_err(
        &mut state,
        &Op::Unlock {
            path: b"/missing".to_vec(),
            session: SESSION_A,
            start: 0,
            end: 1,
        },
        Errno::ENOENT,
    );
}

// ---------------------------------------------------------------------------
// Paths, chunks and invariants
// ---------------------------------------------------------------------------

#[test]
fn u_state_path_rules() {
    let mut state = State::new();
    create_file(&mut state, "/f", 1);
    for path in [
        b"".as_slice(),
        b"relative",
        b"/.",
        b"/..",
        b"/a/../b",
        b"//a",
        b"/a//b",
        b"/a/",
        b"/a\0b",
    ] {
        let op = Op::CreateFile {
            path: path.to_vec(),
            ino: 9,
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime_ns: 0,
        };
        assert!(
            matches!(state.plan(&op), Verdict::Reject(_)),
            "path {:?} should be rejected",
            path
        );
    }
    let long_name = vec![b'a'; MAX_NAME_BYTES + 1];
    let mut long_path = vec![b'/'];
    long_path.extend_from_slice(&long_name);
    let op = Op::CreateFile {
        path: long_path,
        ino: 9,
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime_ns: 0,
    };
    plan_err(&state, &op, Errno::ENAMETOOLONG);

    let mut too_long = vec![b'/'];
    too_long.extend(std::iter::repeat_n(b'a', MAX_PATH_BYTES));
    let op = Op::CreateFile {
        path: too_long,
        ino: 9,
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime_ns: 0,
    };
    plan_err(&state, &op, Errno::ENAMETOOLONG);

    apply_err(
        &mut state,
        &Op::CreateFile {
            path: b"/f/child".to_vec(),
            ino: 9,
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime_ns: 0,
        },
        Errno::ENOTDIR,
    );
    assert_eq!(state.check_invariants(), Ok(()));
}

#[test]
fn u_state_chunk_validation_and_roots() {
    assert_eq!(validate_chunks(&[]), Ok((0, empty_file_root())));
    assert_ne!(empty_file_root(), dir_root());
    assert_ne!(empty_file_root(), symlink_root(b""));
    assert_ne!(file_root(&[full(1)]), file_root(&[full(2)]));
    assert_ne!(
        file_root(&[full(1), full(2)]),
        file_root(&[full(2), full(1)])
    );

    let ok = vec![full(1), part(2, 1)];
    assert_eq!(validate_chunks(&ok), Ok((CHUNK_BYTES + 1, file_root(&ok))));
    assert!(validate_chunks(&[part(1, 0)]).is_err());
    assert!(validate_chunks(&[part(1, 1), part(2, 1)]).is_err());
    assert!(validate_chunks(&[part(1, (CHUNK_BYTES + 1) as u32)]).is_err());
}

#[test]
fn u_state_invariants_report_corruption() {
    let mut state = State::new();
    state.commit(vec![Change::InsertObject(Object {
        ino: 1,
        kind: Kind::File,
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime_ns: 0,
        size: 1,
        file_root: empty_file_root(),
        nlink: 1,
        target: None,
    })]);
    assert!(state.check_invariants().is_err());

    let mut state = State::new();
    state.commit(vec![
        Change::InsertObject(Object {
            ino: 1,
            kind: Kind::File,
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime_ns: 0,
            size: 0,
            file_root: empty_file_root(),
            nlink: 1,
            target: None,
        }),
        Change::InsertName {
            parent: ROOT,
            name: b"f".to_vec(),
            ino: 1,
        },
    ]);
    assert_eq!(state.check_invariants(), Ok(()));
}

// ---------------------------------------------------------------------------
// Random determinism
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn pick(&mut self, values: &[&str]) -> String {
        let index = (self.next() as usize) % values.len();
        values[index].to_string()
    }

    fn chunks(&mut self) -> Vec<Chunk> {
        let count = (self.next() % 4) as usize;
        let mut chunks = Vec::with_capacity(count);
        for index in 0..count {
            let seed = (self.next() % 200) as u8;
            let len = if index + 1 == count {
                1 + (self.next() % CHUNK_BYTES) as u32
            } else {
                CHUNK_BYTES as u32
            };
            chunks.push(part(seed, len));
        }
        chunks
    }
}

fn random_op(rng: &mut Rng, step: u64) -> Op {
    let paths = [
        "/a", "/b", "/c", "/a/f", "/a/g", "/b/h", "/a/d", "/b/d", "/a/d/x", "/b/d/y",
    ];
    let ino = 100 + (rng.next() % 20) as Ino;
    let mtime = step;
    match rng.next() % 13 {
        0 => Op::CreateFile {
            path: rng.pick(&paths).into_bytes(),
            ino,
            mode: 0o644,
            uid: 1,
            gid: 2,
            mtime_ns: mtime,
        },
        1 => Op::CreateDir {
            path: rng.pick(&paths).into_bytes(),
            ino,
            mode: 0o755,
            uid: 1,
            gid: 2,
            mtime_ns: mtime,
        },
        2 => Op::Symlink {
            path: rng.pick(&paths).into_bytes(),
            ino,
            target: b"/target".to_vec(),
            uid: 1,
            gid: 2,
            mtime_ns: mtime,
        },
        3 => Op::Write {
            path: rng.pick(&paths).into_bytes(),
            chunks: rng.chunks(),
            mtime_ns: mtime,
        },
        4 => {
            let chunks = rng.chunks();
            let size = chunks.iter().map(|chunk| u64::from(chunk.len)).sum();
            Op::Truncate {
                path: rng.pick(&paths).into_bytes(),
                size,
                chunks,
                mtime_ns: mtime,
            }
        }
        5 => Op::SetAttr {
            path: rng.pick(&paths).into_bytes(),
            attrs: Attrs {
                mode: Some(0o600),
                uid: Some(3),
                gid: Some(4),
                mtime_ns: Some(mtime),
            },
            size: None,
            chunks: Vec::new(),
        },
        6 => Op::Rename {
            from: rng.pick(&paths).into_bytes(),
            to: rng.pick(&paths).into_bytes(),
            mtime_ns: mtime,
        },
        7 => Op::Unlink {
            path: rng.pick(&paths).into_bytes(),
            mtime_ns: mtime,
        },
        8 => Op::Rmdir {
            path: rng.pick(&paths).into_bytes(),
            mtime_ns: mtime,
        },
        9 => Op::Link {
            target: rng.pick(&paths).into_bytes(),
            path: rng.pick(&paths).into_bytes(),
            mtime_ns: mtime,
        },
        10 => {
            let start = rng.next() % 100;
            let end = start + (rng.next() % 20);
            Op::Lock {
                path: rng.pick(&paths).into_bytes(),
                session: if rng.next() % 2 == 0 {
                    SESSION_A
                } else {
                    SESSION_B
                },
                typ: if rng.next() % 2 == 0 {
                    LockType::Read
                } else {
                    LockType::Write
                },
                start,
                end,
            }
        }
        11 => {
            let start = rng.next() % 100;
            let end = start + (rng.next() % 20);
            Op::Unlock {
                path: rng.pick(&paths).into_bytes(),
                session: if rng.next() % 2 == 0 {
                    SESSION_A
                } else {
                    SESSION_B
                },
                start,
                end,
            }
        }
        _ => Op::Leave {
            session: if rng.next() % 2 == 0 {
                SESSION_A
            } else {
                SESSION_B
            },
        },
    }
}

fn run_random(seed: u64, steps: u64) -> State {
    let mut rng = Rng(seed);
    let mut state = State::new();
    for step in 0..steps {
        let op = random_op(&mut rng, step);
        match state.apply(&op) {
            Ok(()) => {
                assert_eq!(
                    state.check_invariants(),
                    Ok(()),
                    "step {step} after {}",
                    op.name()
                );
            }
            Err(reject) => {
                assert!(
                    !matches!(reject.errno, Errno::EIO | Errno::ENOSYS),
                    "step {step} {}: {reject}",
                    op.name()
                );
            }
        }
    }
    state
}

#[test]
fn u_state_random_sequences_are_deterministic() {
    let first = run_random(0x5eed, 400);
    let second = run_random(0x5eed, 400);
    assert_eq!(first.digest(), second.digest());
    assert_eq!(first.check_invariants(), Ok(()));
    assert_eq!(second.check_invariants(), Ok(()));
    assert_eq!(first.len(), second.len());
    assert_eq!(first.locks().count(), second.locks().count());

    let different = run_random(0x5eed + 1, 400);
    assert_ne!(first.digest(), different.digest());
}
