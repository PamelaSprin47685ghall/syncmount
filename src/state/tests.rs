//! Tests for the pure state machine.
//!
//! Every successful operation goes through [`must_apply`], which checks the
//! structural invariants after the commit. Rejections are checked through
//! [`expect_reject`]; no test calls `unwrap` or `expect`.

use super::*;

const S1: Session = [0x11; 16];
const S2: Session = [0x22; 16];
const S3: Session = [0x33; 16];

fn path(p: &str) -> Path {
    p.as_bytes().to_vec()
}
fn hash(byte: u8) -> Hash {
    [byte; 32]
}
fn chunk(byte: u8, len: u32) -> Chunk {
    Chunk {
        hash: hash(byte),
        len,
    }
}
fn full(byte: u8) -> Chunk {
    chunk(byte, CHUNK_BYTES as u32)
}

fn create_file_at(p: Path, ino: Ino) -> Op {
    Op::CreateFile {
        path: p,
        ino,
        mode: 0o644,
        uid: 1000,
        gid: 1000,
        mtime_ns: 10,
    }
}

fn file_op(p: &str, ino: Ino) -> Op {
    create_file_at(path(p), ino)
}

fn dir_op(p: &str, ino: Ino) -> Op {
    Op::CreateDir {
        path: path(p),
        ino,
        mode: 0o755,
        uid: 1000,
        gid: 1000,
        mtime_ns: 20,
    }
}

fn symlink_op(p: &str, ino: Ino, target: &str) -> Op {
    Op::Symlink {
        path: path(p),
        ino,
        target: target.as_bytes().to_vec(),
        uid: 1000,
        gid: 1000,
        mtime_ns: 30,
    }
}

fn write_op(p: &str, chunks: Vec<Chunk>, mtime_ns: u64) -> Op {
    Op::Write {
        path: path(p),
        chunks,
        mtime_ns,
    }
}

fn truncate_op(p: &str, size: u64, chunks: Vec<Chunk>, mtime_ns: u64) -> Op {
    Op::Truncate {
        path: path(p),
        size,
        chunks,
        mtime_ns,
    }
}

fn set_attr(p: &str, attrs: Attrs) -> Op {
    Op::SetAttr {
        path: path(p),
        attrs,
        size: None,
        chunks: Vec::new(),
    }
}

fn rename_op(from: &str, to: &str, mtime_ns: u64) -> Op {
    Op::Rename {
        from: path(from),
        to: path(to),
        mtime_ns,
    }
}

fn unlink_op(p: &str, mtime_ns: u64) -> Op {
    Op::Unlink {
        path: path(p),
        mtime_ns,
    }
}
fn rmdir_op(p: &str, mtime_ns: u64) -> Op {
    Op::Rmdir {
        path: path(p),
        mtime_ns,
    }
}

fn link_op(target: &str, p: &str, mtime_ns: u64) -> Op {
    Op::Link {
        target: path(target),
        path: path(p),
        mtime_ns,
    }
}

fn lock_op(p: &str, session: Session, typ: LockType, start: u64, end: u64) -> Op {
    Op::Lock {
        path: path(p),
        session,
        typ,
        start,
        end,
    }
}

fn unlock_op(p: &str, session: Session, start: u64, end: u64) -> Op {
    Op::Unlock {
        path: path(p),
        session,
        start,
        end,
    }
}

fn object(state: &State, ino: Ino) -> &Object {
    match state.object(ino) {
        Some(object) => object,
        None => panic!("object {ino} missing"),
    }
}

fn plan_ok(state: &State, op: &Op) -> Vec<Change> {
    match state.plan(op) {
        Verdict::Apply(changes) => changes,
        Verdict::Reject(reject) => panic!("expected Apply, got {reject}"),
    }
}

fn expect_reject(state: &State, op: &Op, errno: Errno) {
    match state.plan(op) {
        Verdict::Reject(reject) => {
            assert_eq!(reject.errno.0, errno.0, "wrong errno: {}", reject.reason)
        }
        Verdict::Apply(_) => panic!("expected errno {}, got Apply", errno.0),
    }
}

fn must_apply(state: &mut State, op: &Op) -> Vec<Change> {
    let changes = plan_ok(state, op);
    match state.apply(op) {
        Ok(()) => {}
        Err(reject) => panic!("apply rejected after plan: {reject}"),
    }
    match state.check_invariants() {
        Ok(()) => {}
        Err(why) => panic!("invariant broken after apply: {why}"),
    }
    changes
}

fn resolve_ok(state: &State, p: &str) -> Ino {
    match state.resolve(p.as_bytes()) {
        Ok(ino) => ino,
        Err(reject) => panic!("resolve {p} failed: {reject}"),
    }
}

fn resolve_err(state: &State, p: &[u8], errno: Errno) {
    match state.resolve(p) {
        Ok(ino) => panic!("resolve unexpectedly returned {ino}"),
        Err(reject) => assert_eq!(reject.errno.0, errno.0, "wrong errno: {}", reject.reason),
    }
}

fn validate_reject(chunks: &[Chunk], errno: Errno) {
    match validate_chunks(chunks) {
        Ok(_) => panic!("expected chunk rejection"),
        Err(reject) => assert_eq!(reject.errno.0, errno.0, "wrong errno: {}", reject.reason),
    }
}

fn has_insert_object(changes: &[Change], ino: Ino) -> bool {
    changes
        .iter()
        .any(|c| matches!(c, Change::InsertObject(o) if o.ino == ino))
}

fn has_insert_name(changes: &[Change], parent: Ino, name: &[u8], ino: Ino) -> bool {
    changes.iter().any(|c| {
        matches!(c, Change::InsertName { parent: p, name: n, ino: i }
            if *p == parent && n.as_slice() == name && *i == ino)
    })
}

fn has_remove_name(changes: &[Change], parent: Ino, name: &[u8]) -> bool {
    changes.iter().any(|c| {
        matches!(c, Change::RemoveName { parent: p, name: n }
            if *p == parent && n.as_slice() == name)
    })
}

fn has_remove_object(changes: &[Change], ino: Ino) -> bool {
    changes
        .iter()
        .any(|c| matches!(c, Change::RemoveObject { ino: i } if *i == ino))
}

fn has_update_chunks(changes: &[Change], ino: Ino) -> bool {
    changes
        .iter()
        .any(|c| matches!(c, Change::UpdateChunks { ino: i, .. } if *i == ino))
}

fn has_insert_lock(changes: &[Change], ino: Ino, start: u64, end: u64, session: Session) -> bool {
    changes.iter().any(|c| {
        matches!(c, Change::InsertLock { key, session: s, .. }
            if key.ino == ino && key.start == start && key.end == end && *s == session)
    })
}

fn has_remove_locks(changes: &[Change], session: Session, ino: Ino, start: u64, end: u64) -> bool {
    changes.iter().any(|c| {
        matches!(c, Change::RemoveLocks { session: s, ino: i, start: a, end: b }
            if *s == session && *i == ino && *a == start && *b == end)
    })
}

fn has_remove_session_locks(changes: &[Change], session: Session) -> bool {
    changes
        .iter()
        .any(|c| matches!(c, Change::RemoveSessionLocks { session: s } if *s == session))
}

fn lock_snapshot(state: &State) -> Vec<(Ino, u64, u64, Session, bool)> {
    let mut rows: Vec<_> = state
        .locks()
        .map(|(key, lock)| {
            (
                key.ino,
                key.start,
                key.end,
                lock.session,
                lock.typ == LockType::Write,
            )
        })
        .collect();
    rows.sort();
    rows
}

fn tree() -> State {
    let mut state = State::new();
    must_apply(&mut state, &dir_op("/x", 1));
    must_apply(&mut state, &dir_op("/y", 2));
    must_apply(&mut state, &file_op("/x/a", 3));
    must_apply(&mut state, &file_op("/y/b", 4));
    must_apply(&mut state, &file_op("/f", 5));
    assert_eq!(object(&state, ROOT).nlink, 4);
    assert_eq!(object(&state, 1).nlink, 2);
    assert_eq!(object(&state, 2).nlink, 2);
    state
}

#[test]
fn u_state_root_and_create_file() {
    let mut state = State::new();
    assert!(matches!(state.check_invariants(), Ok(())));
    {
        let root = object(&state, ROOT);
        assert_eq!(root.ino, ROOT);
        assert_eq!(root.kind, Kind::Dir);
        assert_eq!(
            (root.mode, root.uid, root.gid, root.mtime_ns),
            (0o755, 0, 0, 0)
        );
        assert_eq!(root.nlink, 2);
        assert_eq!((root.size, root.file_root), (0, dir_root()));
        assert!(root.target.is_none());
    }
    assert_eq!(resolve_ok(&state, "/"), ROOT);
    assert!(state.lookup(ROOT, b"nope").is_none());
    assert_eq!(state.len(), 1);
    assert!(state.is_empty());

    let changes = must_apply(&mut state, &file_op("/a", 1));
    assert!(has_insert_object(&changes, 1));
    assert!(has_insert_name(&changes, ROOT, b"a", 1));
    let object_pos = changes
        .iter()
        .position(|c| matches!(c, Change::InsertObject(o) if o.ino == 1));
    let name_pos = changes
        .iter()
        .position(|c| matches!(c, Change::InsertName { ino: i, .. } if *i == 1));
    match (object_pos, name_pos) {
        (Some(object_pos), Some(name_pos)) => assert!(object_pos < name_pos),
        _ => panic!("create changes missing object or name"),
    }
    {
        let file = object(&state, 1);
        assert_eq!(file.kind, Kind::File);
        assert_eq!(
            (file.mode, file.uid, file.gid, file.mtime_ns),
            (0o644, 1000, 1000, 10)
        );
        assert_eq!((file.nlink, file.size), (1, 0));
        assert_eq!(file.file_root, empty_file_root());
        assert!(file.target.is_none());
    }
    assert_eq!(state.lookup(ROOT, b"a"), Some(1));
    assert!(state.chunks(1).is_empty());
    assert_eq!(
        (object(&state, ROOT).nlink, object(&state, ROOT).mtime_ns),
        (2, 10)
    );
    assert_eq!(state.len(), 2);
    assert!(!state.is_empty());

    expect_reject(&state, &file_op("/a", 2), Errno::EEXIST);
    expect_reject(&state, &file_op("/", 2), Errno::EEXIST);
    expect_reject(&state, &file_op("/b", 1), Errno::EEXIST);
    expect_reject(&state, &file_op("/b", ROOT), Errno::EEXIST);
    expect_reject(&state, &file_op("/missing/b", 3), Errno::ENOENT);
    must_apply(&mut state, &file_op("/f", 2));
    expect_reject(&state, &file_op("/f/b", 3), Errno::ENOTDIR);
    must_apply(&mut state, &symlink_op("/s", 3, "t"));
    expect_reject(&state, &file_op("/s/b", 4), Errno::ENOTDIR);

    let masked = Op::CreateFile {
        path: path("/m"),
        ino: 4,
        mode: 0o77777,
        uid: 7,
        gid: 8,
        mtime_ns: 11,
    };
    must_apply(&mut state, &masked);
    assert_eq!(object(&state, 4).mode, 0o7777);

    let before = state.digest();
    let _ = state.plan(&file_op("/later", 20));
    assert_eq!(state.digest(), before);
    assert_eq!(
        state.plan(&file_op("/later", 20)).is_apply(),
        plan(&file_op("/later", 20), &state).is_apply()
    );
}

#[test]
fn u_state_create_dir_nlink() {
    let mut state = State::new();
    must_apply(&mut state, &dir_op("/d", 2));
    {
        let dir = object(&state, 2);
        assert_eq!(dir.kind, Kind::Dir);
        assert_eq!((dir.mode, dir.nlink, dir.size), (0o755, 2, 0));
        assert_eq!(dir.file_root, dir_root());
        assert!(dir.target.is_none());
    }
    assert_eq!(object(&state, ROOT).nlink, 3);
    assert_eq!(state.lookup(ROOT, b"d"), Some(2));

    must_apply(&mut state, &dir_op("/d/e", 3));
    assert_eq!(
        (object(&state, 2).nlink, object(&state, ROOT).nlink),
        (3, 3)
    );
    must_apply(&mut state, &dir_op("/d/e/f", 4));
    assert_eq!(
        (
            object(&state, 3).nlink,
            object(&state, 2).nlink,
            object(&state, ROOT).nlink
        ),
        (3, 3, 3)
    );

    expect_reject(&state, &dir_op("/d", 5), Errno::EEXIST);
    expect_reject(&state, &dir_op("/d2", 2), Errno::EEXIST);
    expect_reject(&state, &dir_op("/", 5), Errno::EEXIST);
    expect_reject(&state, &dir_op("/missing/d", 5), Errno::ENOENT);
    must_apply(&mut state, &file_op("/f", 5));
    expect_reject(&state, &dir_op("/f/g", 6), Errno::ENOTDIR);

    let masked = Op::CreateDir {
        path: path("/masked"),
        ino: 6,
        mode: 0o77777,
        uid: 1,
        gid: 2,
        mtime_ns: 12,
    };
    must_apply(&mut state, &masked);
    assert_eq!(object(&state, 6).mode, 0o7777);
}

#[test]
fn u_state_symlink_create_and_validate() {
    let mut state = State::new();
    expect_reject(&state, &symlink_op("/s", 2, ""), Errno::EINVAL);
    expect_reject(
        &state,
        &Op::Symlink {
            path: path("/s"),
            ino: 2,
            target: vec![b'x'; MAX_PATH_BYTES + 1],
            uid: 1,
            gid: 2,
            mtime_ns: 3,
        },
        Errno::ENAMETOOLONG,
    );
    expect_reject(
        &state,
        &Op::Symlink {
            path: path("/s"),
            ino: 2,
            target: b"a\0b".to_vec(),
            uid: 1,
            gid: 2,
            mtime_ns: 3,
        },
        Errno::EINVAL,
    );

    let target = "target";
    let changes = must_apply(&mut state, &symlink_op("/s", 2, target));
    assert!(has_insert_object(&changes, 2));
    assert!(has_insert_name(&changes, ROOT, b"s", 2));
    {
        let link = object(&state, 2);
        assert_eq!(link.kind, Kind::Symlink);
        assert_eq!((link.mode, link.nlink), (0o777, 1));
        assert_eq!(link.size, target.len() as u64);
        assert_eq!(link.file_root, symlink_root(target.as_bytes()));
        assert_eq!(link.target.as_deref(), Some(target.as_bytes()));
    }
    assert_eq!(resolve_ok(&state, "/s"), 2);
    expect_reject(&state, &file_op("/s/x", 3), Errno::ENOTDIR);
    resolve_err(&state, b"/s/x", Errno::ENOTDIR);

    must_apply(
        &mut state,
        &Op::Symlink {
            path: path("/long"),
            ino: 3,
            target: vec![b'y'; MAX_PATH_BYTES],
            uid: 1,
            gid: 2,
            mtime_ns: 4,
        },
    );
    assert_eq!(object(&state, 3).size, MAX_PATH_BYTES as u64);

    expect_reject(&state, &symlink_op("/s", 4, "other"), Errno::EEXIST);
    expect_reject(&state, &symlink_op("/missing/s", 4, "x"), Errno::ENOENT);
    must_apply(&mut state, &file_op("/f", 4));
    expect_reject(&state, &symlink_op("/f/s", 5, "x"), Errno::ENOTDIR);
    expect_reject(&state, &symlink_op("/", 5, "x"), Errno::EEXIST);
    expect_reject(&state, &symlink_op("/ino", 2, "x"), Errno::EEXIST);
}

#[test]
fn u_state_write_chunks() {
    let mut state = State::new();
    must_apply(&mut state, &file_op("/f", 1));

    let changes = must_apply(&mut state, &write_op("/f", Vec::new(), 100));
    assert!(has_update_chunks(&changes, 1));
    assert_eq!(
        (object(&state, 1).size, object(&state, 1).file_root),
        (0, empty_file_root())
    );
    assert_eq!(object(&state, 1).mtime_ns, 100);
    assert!(state.chunks(1).is_empty());

    let full_chunks = vec![full(0xA1)];
    let full_root = file_root(&full_chunks);
    must_apply(&mut state, &write_op("/f", full_chunks, 101));
    assert_eq!(
        (object(&state, 1).size, object(&state, 1).file_root),
        (CHUNK_BYTES, full_root)
    );
    assert_eq!(object(&state, 1).mtime_ns, 101);
    assert_eq!(state.chunks(1), &[full(0xA1)][..]);

    let tail_chunks = vec![full(0xA2), chunk(0xB3, 100)];
    let tail_root = file_root(&tail_chunks);
    must_apply(&mut state, &write_op("/f", tail_chunks, 102));
    assert_eq!(object(&state, 1).size, CHUNK_BYTES + 100);
    assert_eq!(object(&state, 1).file_root, tail_root);
    assert_eq!(state.chunks(1), &[full(0xA2), chunk(0xB3, 100)][..]);

    must_apply(
        &mut state,
        &write_op("/f", vec![full(0xC4), full(0xD5)], 103),
    );
    assert_eq!(object(&state, 1).size, 2 * CHUNK_BYTES);

    expect_reject(
        &state,
        &write_op("/f", vec![chunk(1, 100), full(2)], 104),
        Errno::EINVAL,
    );
    expect_reject(
        &state,
        &write_op("/f", vec![chunk(1, 0)], 104),
        Errno::EINVAL,
    );
    expect_reject(
        &state,
        &write_op("/f", vec![full(1), chunk(2, 0)], 104),
        Errno::EINVAL,
    );

    must_apply(&mut state, &dir_op("/d", 2));
    must_apply(&mut state, &symlink_op("/s", 3, "t"));
    expect_reject(&state, &write_op("/d", Vec::new(), 105), Errno::EISDIR);
    expect_reject(&state, &write_op("/s", Vec::new(), 105), Errno::EINVAL);
    expect_reject(
        &state,
        &write_op("/missing", Vec::new(), 105),
        Errno::ENOENT,
    );
}

#[test]
fn u_state_truncate_chunks() {
    let mut state = State::new();
    must_apply(&mut state, &file_op("/f", 1));
    must_apply(
        &mut state,
        &write_op("/f", vec![full(0xA1), chunk(0xB2, 100)], 100),
    );

    let tail = vec![chunk(0xC3, 50)];
    let tail_root = file_root(&tail);
    must_apply(&mut state, &truncate_op("/f", 50, tail, 101));
    assert_eq!(
        (object(&state, 1).size, object(&state, 1).file_root),
        (50, tail_root)
    );
    assert_eq!(object(&state, 1).mtime_ns, 101);
    assert_eq!(state.chunks(1), &[chunk(0xC3, 50)][..]);

    must_apply(&mut state, &truncate_op("/f", 0, Vec::new(), 102));
    assert_eq!(
        (object(&state, 1).size, object(&state, 1).file_root),
        (0, empty_file_root())
    );

    expect_reject(
        &state,
        &truncate_op("/f", 49, vec![chunk(0xC3, 50)], 103),
        Errno::EINVAL,
    );
    expect_reject(
        &state,
        &truncate_op("/f", 0, vec![chunk(0xC3, 50)], 103),
        Errno::EINVAL,
    );
    expect_reject(
        &state,
        &truncate_op("/f", 100, vec![chunk(0xC3, 50)], 103),
        Errno::EINVAL,
    );
    expect_reject(
        &state,
        &truncate_op("/f", 65636, vec![chunk(1, 100), full(2)], 103),
        Errno::EINVAL,
    );
    expect_reject(
        &state,
        &truncate_op("/f", 0, vec![chunk(1, 0)], 103),
        Errno::EINVAL,
    );

    must_apply(&mut state, &dir_op("/d", 2));
    must_apply(&mut state, &symlink_op("/s", 3, "t"));
    expect_reject(
        &state,
        &truncate_op("/d", 0, Vec::new(), 104),
        Errno::EISDIR,
    );
    expect_reject(
        &state,
        &truncate_op("/s", 0, Vec::new(), 104),
        Errno::EINVAL,
    );
    expect_reject(
        &state,
        &truncate_op("/missing", 0, Vec::new(), 104),
        Errno::ENOENT,
    );
}

#[test]
fn u_state_validate_chunks_and_roots() {
    assert_eq!(file_root(&[]), empty_file_root());
    assert_ne!(dir_root(), empty_file_root());
    assert_eq!(symlink_root(b"a"), symlink_root(b"a"));
    assert_ne!(symlink_root(b"a"), symlink_root(b"b"));

    match validate_chunks(&[]) {
        Ok((size, root)) => assert_eq!((size, root), (0, empty_file_root())),
        Err(reject) => panic!("empty chunks rejected: {reject}"),
    }
    let chunks = vec![full(0x11), chunk(0x22, 7)];
    match validate_chunks(&chunks) {
        Ok((size, root)) => {
            assert_eq!(size, CHUNK_BYTES + 7);
            assert_eq!(root, file_root(&chunks));
        }
        Err(reject) => panic!("valid chunks rejected: {reject}"),
    }
    validate_reject(&[chunk(0x33, 0)], Errno::EINVAL);
    validate_reject(&[chunk(0x44, 1), full(0x55)], Errno::EINVAL);
    validate_reject(&[chunk(0x66, CHUNK_BYTES as u32 + 1)], Errno::EINVAL);
}

#[test]
fn u_state_setattr_partial_and_noop() {
    let mut state = State::new();
    must_apply(&mut state, &file_op("/f", 1));

    let changes = must_apply(
        &mut state,
        &set_attr(
            "/f",
            Attrs {
                mode: Some(0o77777),
                ..Attrs::default()
            },
        ),
    );
    assert!(
        changes
            .iter()
            .any(|c| matches!(c, Change::SetAttrs { ino: i, .. } if *i == 1))
    );
    assert_eq!(object(&state, 1).mode, 0o7777);
    assert_eq!(
        (
            object(&state, 1).uid,
            object(&state, 1).gid,
            object(&state, 1).mtime_ns
        ),
        (1000, 1000, 10)
    );

    must_apply(
        &mut state,
        &set_attr(
            "/f",
            Attrs {
                uid: Some(42),
                ..Attrs::default()
            },
        ),
    );
    assert_eq!(
        (object(&state, 1).uid, object(&state, 1).mode),
        (42, 0o7777)
    );
    must_apply(
        &mut state,
        &set_attr(
            "/f",
            Attrs {
                gid: Some(43),
                ..Attrs::default()
            },
        ),
    );
    assert_eq!(object(&state, 1).gid, 43);
    must_apply(
        &mut state,
        &set_attr(
            "/f",
            Attrs {
                mtime_ns: Some(99),
                ..Attrs::default()
            },
        ),
    );
    assert_eq!(object(&state, 1).mtime_ns, 99);

    let before = state.digest();
    let changes = must_apply(&mut state, &set_attr("/f", Attrs::default()));
    assert!(changes.is_empty());
    assert_eq!(state.digest(), before);
    expect_reject(
        &state,
        &set_attr("/missing", Attrs::default()),
        Errno::ENOENT,
    );

    must_apply(&mut state, &dir_op("/d", 2));
    must_apply(
        &mut state,
        &set_attr(
            "/d",
            Attrs {
                mode: Some(0o700),
                ..Attrs::default()
            },
        ),
    );
    assert_eq!(object(&state, 2).mode, 0o700);
}

#[test]
fn u_state_rename_moves() {
    let mut state = tree();
    let changes = must_apply(&mut state, &rename_op("/x/a", "/x/c", 500));
    assert!(has_remove_name(&changes, 1, b"a"));
    assert!(has_insert_name(&changes, 1, b"c", 3));
    assert_eq!(state.lookup(1, b"a"), None);
    assert_eq!(state.lookup(1, b"c"), Some(3));
    assert_eq!(
        (object(&state, 3).mtime_ns, object(&state, 1).mtime_ns),
        (500, 500)
    );
    assert_eq!(
        (object(&state, 1).nlink, object(&state, ROOT).nlink),
        (2, 4)
    );

    let mut state = tree();
    must_apply(&mut state, &rename_op("/x/a", "/y/a", 501));
    assert_eq!(state.lookup(1, b"a"), None);
    assert_eq!(state.lookup(2, b"a"), Some(3));
    assert_eq!(
        (
            object(&state, 3).mtime_ns,
            object(&state, 1).mtime_ns,
            object(&state, 2).mtime_ns
        ),
        (501, 501, 501)
    );
    assert_eq!((object(&state, 1).nlink, object(&state, 2).nlink), (2, 2));
    assert_eq!(object(&state, ROOT).nlink, 4);

    let mut state = tree();
    must_apply(&mut state, &rename_op("/x", "/y/x", 502));
    assert_eq!(state.lookup(ROOT, b"x"), None);
    assert_eq!(state.lookup(2, b"x"), Some(1));
    assert_eq!(
        (
            object(&state, ROOT).nlink,
            object(&state, 2).nlink,
            object(&state, 1).nlink
        ),
        (3, 3, 2)
    );
    assert_eq!(
        (
            object(&state, 1).mtime_ns,
            object(&state, ROOT).mtime_ns,
            object(&state, 2).mtime_ns
        ),
        (502, 502, 502)
    );

    let mut state = tree();
    must_apply(&mut state, &rename_op("/x", "/z", 503));
    assert_eq!(state.lookup(ROOT, b"x"), None);
    assert_eq!(state.lookup(ROOT, b"z"), Some(1));
    assert_eq!(
        (object(&state, ROOT).nlink, object(&state, 1).nlink),
        (4, 2)
    );
}

#[test]
fn u_state_rename_overwrites() {
    let mut state = tree();
    let changes = must_apply(&mut state, &rename_op("/x/a", "/y/b", 504));
    assert!(has_remove_name(&changes, 1, b"a"));
    assert!(has_remove_name(&changes, 2, b"b"));
    assert!(has_insert_name(&changes, 2, b"b", 3));
    assert!(has_remove_object(&changes, 4));
    let old = changes
        .iter()
        .position(|c| matches!(c, Change::RemoveName { parent, .. } if *parent == 1));
    let new = changes
        .iter()
        .position(|c| matches!(c, Change::RemoveName { parent, .. } if *parent == 2));
    let removed = changes
        .iter()
        .position(|c| matches!(c, Change::RemoveObject { ino: i } if *i == 4));
    match (old, new, removed) {
        (Some(old), Some(new), Some(removed)) => assert!(old < new && new < removed),
        _ => panic!("rename changes missing or out of order"),
    }
    assert_eq!(state.lookup(1, b"a"), None);
    assert_eq!(state.lookup(2, b"b"), Some(3));
    assert!(state.object(4).is_none());
    assert_eq!(
        (object(&state, 3).nlink, object(&state, 3).mtime_ns),
        (1, 504)
    );
    assert_eq!((object(&state, 1).nlink, object(&state, 2).nlink), (2, 2));

    let mut state = tree();
    must_apply(&mut state, &link_op("/f", "/g", 505));
    must_apply(&mut state, &rename_op("/x/a", "/g", 506));
    assert_eq!(
        (state.lookup(ROOT, b"f"), state.lookup(ROOT, b"g")),
        (Some(5), Some(3))
    );
    assert_eq!((object(&state, 5).nlink, object(&state, 3).nlink), (1, 1));
    assert!(state.object(4).is_some());

    let mut state = tree();
    must_apply(&mut state, &symlink_op("/s", 6, "target"));
    must_apply(&mut state, &rename_op("/f", "/s", 507));
    assert!(state.object(6).is_none());
    assert_eq!(
        (state.lookup(ROOT, b"s"), state.lookup(ROOT, b"f")),
        (Some(5), None)
    );
    assert_eq!(object(&state, 5).nlink, 1);

    let mut state = tree();
    must_apply(&mut state, &dir_op("/x/empty", 6));
    must_apply(&mut state, &rename_op("/y", "/x/empty", 508));
    assert_eq!(state.lookup(ROOT, b"y"), None);
    assert_eq!(state.lookup(1, b"empty"), Some(2));
    assert!(state.object(6).is_none());
    assert_eq!(
        (
            object(&state, ROOT).nlink,
            object(&state, 1).nlink,
            object(&state, 2).nlink
        ),
        (3, 3, 2)
    );
    assert_eq!(object(&state, 2).mtime_ns, 508);

    let mut state = tree();
    must_apply(&mut state, &dir_op("/d1", 6));
    must_apply(&mut state, &dir_op("/d2", 7));
    assert_eq!(object(&state, ROOT).nlink, 6);
    must_apply(&mut state, &rename_op("/d1", "/d2", 509));
    assert_eq!(state.lookup(ROOT, b"d1"), None);
    assert_eq!(state.lookup(ROOT, b"d2"), Some(6));
    assert!(state.object(7).is_none());
    assert_eq!(
        (object(&state, ROOT).nlink, object(&state, 6).nlink),
        (5, 2)
    );
}

#[test]
fn u_state_rename_conflicts() {
    let mut state = tree();
    expect_reject(&state, &rename_op("/x", "/f", 510), Errno::ENOTDIR);
    expect_reject(&state, &rename_op("/f", "/x", 510), Errno::EISDIR);
    expect_reject(&state, &rename_op("/x", "/y", 510), Errno::ENOTEMPTY);
    must_apply(&mut state, &dir_op("/x/sub", 6));
    expect_reject(&state, &rename_op("/x", "/x/sub", 510), Errno::EINVAL);
    expect_reject(&state, &rename_op("/x/a", "/missing/a", 510), Errno::ENOENT);
    expect_reject(&state, &rename_op("/x/a", "/f/a", 510), Errno::ENOTDIR);
    expect_reject(&state, &rename_op("/missing", "/z", 510), Errno::ENOENT);
    expect_reject(&state, &rename_op("/", "/z", 510), Errno::EBUSY);
    expect_reject(&state, &rename_op("/x/a", "/", 510), Errno::EBUSY);
}

#[test]
fn u_state_rename_noop() {
    let mut state = tree();
    let before = state.digest();
    let changes = must_apply(&mut state, &rename_op("/x/a", "/x/a", 511));
    assert!(changes.is_empty());
    assert_eq!(state.digest(), before);
    assert_eq!(object(&state, 3).mtime_ns, 10);

    must_apply(&mut state, &link_op("/f", "/g", 512));
    let before = state.digest();
    let changes = must_apply(&mut state, &rename_op("/f", "/g", 513));
    assert!(changes.is_empty());
    assert_eq!(state.digest(), before);
    assert_eq!(object(&state, 5).mtime_ns, 10);
}

#[test]
fn u_state_unlink_and_hardlinks() {
    let mut state = State::new();
    must_apply(&mut state, &file_op("/a", 1));
    must_apply(&mut state, &file_op("/b", 2));
    must_apply(&mut state, &link_op("/a", "/c", 200));
    assert_eq!(
        (object(&state, 1).nlink, object(&state, 1).mtime_ns),
        (2, 10)
    );
    assert_eq!(state.lookup(ROOT, b"c"), Some(1));

    let changes = must_apply(&mut state, &unlink_op("/a", 201));
    assert!(has_remove_name(&changes, ROOT, b"a"));
    assert_eq!(
        (state.lookup(ROOT, b"a"), state.lookup(ROOT, b"c")),
        (None, Some(1))
    );
    assert_eq!(object(&state, 1).nlink, 1);
    assert_eq!(object(&state, ROOT).mtime_ns, 201);

    must_apply(&mut state, &unlink_op("/c", 202));
    assert!(state.object(1).is_none());
    must_apply(&mut state, &unlink_op("/b", 203));
    assert!(state.object(2).is_none());

    expect_reject(&state, &unlink_op("/missing", 204), Errno::ENOENT);
    expect_reject(&state, &unlink_op("/", 204), Errno::EBUSY);
    must_apply(&mut state, &dir_op("/d", 3));
    expect_reject(&state, &unlink_op("/d", 204), Errno::EISDIR);
    must_apply(&mut state, &symlink_op("/s", 4, "t"));
    must_apply(&mut state, &unlink_op("/s", 205));
    assert!(state.object(4).is_none());
}

#[test]
fn u_state_rmdir_rules() {
    let mut state = State::new();
    must_apply(&mut state, &dir_op("/d", 1));
    assert_eq!(object(&state, ROOT).nlink, 3);
    must_apply(&mut state, &file_op("/d/f", 2));
    expect_reject(&state, &rmdir_op("/d", 300), Errno::ENOTEMPTY);
    must_apply(&mut state, &unlink_op("/d/f", 301));
    let changes = must_apply(&mut state, &rmdir_op("/d", 302));
    assert!(has_remove_name(&changes, ROOT, b"d"));
    assert!(has_remove_object(&changes, 1));
    assert_eq!(
        (object(&state, ROOT).nlink, object(&state, ROOT).mtime_ns),
        (2, 302)
    );

    expect_reject(&state, &rmdir_op("/", 303), Errno::EBUSY);
    expect_reject(&state, &rmdir_op("/missing", 303), Errno::ENOENT);
    must_apply(&mut state, &file_op("/f", 3));
    expect_reject(&state, &rmdir_op("/f", 303), Errno::ENOTDIR);
    must_apply(&mut state, &symlink_op("/s", 4, "t"));
    expect_reject(&state, &rmdir_op("/s", 303), Errno::ENOTDIR);
}

#[test]
fn u_state_link_rules() {
    let mut state = State::new();
    must_apply(&mut state, &file_op("/a", 1));
    must_apply(&mut state, &dir_op("/d", 2));
    must_apply(&mut state, &symlink_op("/s", 3, "t"));

    let changes = must_apply(&mut state, &link_op("/a", "/b", 400));
    assert!(has_insert_name(&changes, ROOT, b"b", 1));
    assert_eq!(
        (object(&state, 1).nlink, object(&state, 1).mtime_ns),
        (2, 10)
    );
    assert_eq!(object(&state, ROOT).mtime_ns, 400);
    must_apply(&mut state, &link_op("/s", "/s2", 401));
    assert_eq!(object(&state, 3).nlink, 2);

    expect_reject(&state, &link_op("/d", "/d2", 402), Errno::EPERM);
    expect_reject(&state, &link_op("/a", "/b", 402), Errno::EEXIST);
    expect_reject(&state, &link_op("/missing", "/c", 402), Errno::ENOENT);
    expect_reject(&state, &link_op("/a", "/missing/c", 402), Errno::ENOENT);
    expect_reject(&state, &link_op("/a", "/a/c", 402), Errno::ENOTDIR);
    expect_reject(&state, &link_op("/", "/root2", 402), Errno::EPERM);
    expect_reject(&state, &link_op("/a", "/", 402), Errno::EEXIST);

    must_apply(&mut state, &unlink_op("/a", 403));
    assert_eq!(
        (object(&state, 1).nlink, state.lookup(ROOT, b"b")),
        (1, Some(1))
    );
    must_apply(&mut state, &unlink_op("/b", 404));
    assert!(state.object(1).is_none());
}

#[test]
fn u_state_lock_conflicts() {
    let mut state = State::new();
    must_apply(&mut state, &file_op("/f", 1));
    must_apply(&mut state, &file_op("/g", 2));
    let changes = must_apply(&mut state, &lock_op("/f", S1, LockType::Read, 0, 10));
    assert!(has_insert_lock(&changes, 1, 0, 10, S1));
    assert_eq!(lock_snapshot(&state), vec![(1, 0, 10, S1, false)]);

    must_apply(&mut state, &lock_op("/f", S2, LockType::Read, 5, 15));
    assert_eq!(
        lock_snapshot(&state),
        vec![(1, 0, 10, S1, false), (1, 5, 15, S2, false)]
    );
    expect_reject(
        &state,
        &lock_op("/f", S2, LockType::Write, 5, 8),
        Errno::EAGAIN,
    );
    expect_reject(
        &state,
        &lock_op("/f", S3, LockType::Write, 0, 0),
        Errno::EAGAIN,
    );
    expect_reject(
        &state,
        &lock_op("/f", S3, LockType::Write, 14, 20),
        Errno::EAGAIN,
    );
    must_apply(&mut state, &lock_op("/f", S2, LockType::Write, 16, 20));
    assert_eq!(lock_snapshot(&state).len(), 3);

    must_apply(&mut state, &lock_op("/g", S1, LockType::Write, 0, 10));
    expect_reject(
        &state,
        &lock_op("/g", S2, LockType::Read, 5, 6),
        Errno::EAGAIN,
    );
    expect_reject(
        &state,
        &lock_op("/g", S2, LockType::Write, 5, 6),
        Errno::EAGAIN,
    );
}

#[test]
fn u_state_lock_replace_and_unlock() {
    let mut state = State::new();
    must_apply(&mut state, &file_op("/f", 1));
    must_apply(&mut state, &file_op("/g", 2));
    must_apply(&mut state, &lock_op("/f", S1, LockType::Read, 0, 10));
    let changes = must_apply(&mut state, &lock_op("/f", S1, LockType::Write, 0, 10));
    assert!(has_remove_locks(&changes, S1, 1, 0, 10));
    assert!(has_insert_lock(&changes, 1, 0, 10, S1));
    assert_eq!(lock_snapshot(&state), vec![(1, 0, 10, S1, true)]);

    must_apply(&mut state, &lock_op("/f", S1, LockType::Read, 0, 20));
    assert_eq!(lock_snapshot(&state), vec![(1, 0, 20, S1, false)]);

    must_apply(&mut state, &lock_op("/g", S2, LockType::Write, 0, 10));
    let changes = must_apply(&mut state, &unlock_op("/f", S1, 5, 8));
    assert!(has_remove_locks(&changes, S1, 1, 5, 8));
    assert_eq!(
        lock_snapshot(&state),
        vec![
            (1, 0, 4, S1, false),
            (1, 9, 20, S1, false),
            (2, 0, 10, S2, true),
        ]
    );

    let before = state.digest();
    must_apply(&mut state, &unlock_op("/f", S1, 100, 200));
    assert_eq!(state.digest(), before);

    let changes = must_apply(&mut state, &Op::Leave { session: S1 });
    assert!(has_remove_session_locks(&changes, S1));
    assert_eq!(lock_snapshot(&state), vec![(2, 0, 10, S2, true)]);
    must_apply(&mut state, &Op::Leave { session: S1 });
    must_apply(&mut state, &Op::Leave { session: S3 });

    expect_reject(
        &state,
        &lock_op("/missing", S1, LockType::Read, 0, 1),
        Errno::ENOENT,
    );
    expect_reject(&state, &unlock_op("/missing", S1, 0, 1), Errno::ENOENT);
    expect_reject(
        &state,
        &lock_op("/f", S1, LockType::Read, 5, 4),
        Errno::EINVAL,
    );
    expect_reject(&state, &unlock_op("/f", S1, 5, 4), Errno::EINVAL);
}

#[test]
fn u_state_path_validation() {
    let mut state = State::new();
    must_apply(&mut state, &file_op("/f", 1));
    must_apply(&mut state, &dir_op("/d", 2));
    must_apply(&mut state, &symlink_op("/s", 3, "t"));

    for bad in [
        "", "a", ".", "./a", "/.", "/..", "/a/..", "//", "/d//x", "/d/", "/d/.", "/d/../x",
    ] {
        expect_reject(&state, &file_op(bad, 10), Errno::EINVAL);
        resolve_err(&state, bad.as_bytes(), Errno::EINVAL);
    }
    assert_eq!(resolve_ok(&state, "/"), ROOT);
    resolve_err(&state, b"/missing", Errno::ENOENT);
    expect_reject(&state, &file_op("/missing/x", 10), Errno::ENOENT);
    resolve_err(&state, b"/f/x", Errno::ENOTDIR);
    resolve_err(&state, b"/s/x", Errno::ENOTDIR);
    expect_reject(&state, &file_op("/f/x", 10), Errno::ENOTDIR);
    expect_reject(&state, &file_op("/s/x", 10), Errno::ENOTDIR);
    resolve_err(&state, b"/d/\0x", Errno::EINVAL);
    expect_reject(
        &state,
        &create_file_at(b"/d/\0x".to_vec(), 10),
        Errno::EINVAL,
    );

    let mut ok_name = b"/d/".to_vec();
    ok_name.extend_from_slice(&[b'a'; MAX_NAME_BYTES]);
    must_apply(&mut state, &create_file_at(ok_name, 10));

    let mut long_name = b"/d/".to_vec();
    long_name.extend_from_slice(&[b'a'; MAX_NAME_BYTES + 1]);
    expect_reject(
        &state,
        &create_file_at(long_name.clone(), 11),
        Errno::ENAMETOOLONG,
    );
    resolve_err(&state, &long_name, Errno::ENAMETOOLONG);

    let mut long_path = Vec::new();
    for _ in 0..17 {
        long_path.push(b'/');
        long_path.extend_from_slice(&[b'b'; MAX_NAME_BYTES]);
    }
    assert!(long_path.len() > MAX_PATH_BYTES);
    resolve_err(&state, &long_path, Errno::ENAMETOOLONG);
}

#[test]
fn u_state_commit_matches_apply() {
    let mut by_commit = tree();
    let mut by_apply = tree();
    let op = rename_op("/x/a", "/y/b", 600);
    let changes = plan_ok(&by_commit, &op);
    by_commit.commit(changes);
    match by_apply.apply(&op) {
        Ok(()) => {}
        Err(reject) => panic!("apply failed: {reject}"),
    }
    assert_eq!(by_commit.digest(), by_apply.digest());
    assert!(matches!(by_commit.check_invariants(), Ok(())));
    assert!(matches!(by_apply.check_invariants(), Ok(())));
}

struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
    fn bool(&mut self) -> bool {
        self.next() & 1 == 1
    }
    fn pick<T: Copy>(&mut self, values: &[T]) -> T {
        values[self.below(values.len() as u64) as usize]
    }
}

fn random_chunks(rng: &mut Lcg) -> Vec<Chunk> {
    match rng.below(6) {
        0 => Vec::new(),
        1 => vec![full(rng.byte())],
        2 => vec![
            full(rng.byte()),
            chunk(rng.byte(), 1 + rng.below(CHUNK_BYTES) as u32),
        ],
        3 => vec![chunk(rng.byte(), 1 + rng.below(CHUNK_BYTES) as u32)],
        4 => vec![
            chunk(rng.byte(), 1 + rng.below(100) as u32),
            full(rng.byte()),
        ],
        _ => vec![chunk(rng.byte(), 0)],
    }
}

fn random_range(rng: &mut Lcg) -> (u64, u64) {
    if rng.below(8) == 0 {
        return (20, 10);
    }
    let (a, b) = (rng.below(30), rng.below(30));
    if a <= b { (a, b) } else { (b, a) }
}

fn random_session(rng: &mut Lcg) -> Session {
    match rng.below(3) {
        0 => S1,
        1 => S2,
        _ => S3,
    }
}

fn random_op(rng: &mut Lcg, ino: &mut Ino) -> Op {
    const PATHS: [&str; 12] = [
        "/lock", "/d", "/d/f", "/e", "/e/h", "/s", "/hard", "/missing", "/d/nope", "/e/nope",
        "/d/f/x", "relative",
    ];
    const MUT_PATHS: [&str; 11] = [
        "/d", "/d/f", "/e", "/e/h", "/s", "/hard", "/missing", "/d/nope", "/e/nope", "/d/f/x",
        "relative",
    ];
    let lock_paths = ["/lock/f"];
    let p = rng.pick(&PATHS);
    match rng.below(13) {
        0 => {
            *ino += 1;
            let p = rng.pick(&["/d/new", "/e/new", "/new", "/d/f/x", "/missing/new"]);
            create_file_at(path(p), *ino)
        }
        1 => {
            *ino += 1;
            let p = rng.pick(&["/d/new", "/e/new", "/new", "/d/f/x"]);
            Op::CreateDir {
                path: path(p),
                ino: *ino,
                mode: 0o755,
                uid: 1,
                gid: 2,
                mtime_ns: rng.next(),
            }
        }
        2 => {
            *ino += 1;
            let p = rng.pick(&["/d/new", "/e/new", "/new"]);
            Op::Symlink {
                path: path(p),
                ino: *ino,
                target: rng.pick(&["t", "", "x"]).as_bytes().to_vec(),
                uid: 1,
                gid: 2,
                mtime_ns: rng.next(),
            }
        }
        3 => write_op(p, random_chunks(rng), rng.next()),
        4 => {
            let chunks = random_chunks(rng);
            let size = match validate_chunks(&chunks) {
                Ok((size, _)) => {
                    if rng.bool() {
                        size
                    } else {
                        size.wrapping_add(1)
                    }
                }
                Err(_) => rng.below(100_000),
            };
            truncate_op(p, size, chunks, rng.next())
        }
        5 => set_attr(
            p,
            Attrs {
                mode: if rng.bool() {
                    Some(rng.next() as u32 & 0o77777)
                } else {
                    None
                },
                uid: if rng.bool() {
                    Some(rng.next() as u32)
                } else {
                    None
                },
                gid: if rng.bool() {
                    Some(rng.next() as u32)
                } else {
                    None
                },
                mtime_ns: if rng.bool() { Some(rng.next()) } else { None },
            },
        ),
        6 | 7 => rename_op(rng.pick(&MUT_PATHS), rng.pick(&MUT_PATHS), rng.next()),
        8 => unlink_op(rng.pick(&MUT_PATHS), rng.next()),
        9 => rmdir_op(rng.pick(&MUT_PATHS), rng.next()),
        10 => link_op(rng.pick(&PATHS), rng.pick(&MUT_PATHS), rng.next()),
        11 => {
            let typ = if rng.bool() {
                LockType::Read
            } else {
                LockType::Write
            };
            let (start, end) = random_range(rng);
            lock_op(rng.pick(&lock_paths), random_session(rng), typ, start, end)
        }
        _ => {
            if rng.bool() {
                let (start, end) = random_range(rng);
                unlock_op(rng.pick(&lock_paths), random_session(rng), start, end)
            } else {
                Op::Leave {
                    session: random_session(rng),
                }
            }
        }
    }
}

fn random_setup() -> [Op; 8] {
    [
        dir_op("/lock", 1),
        file_op("/lock/f", 2),
        dir_op("/d", 3),
        file_op("/d/f", 4),
        dir_op("/e", 5),
        file_op("/e/h", 6),
        symlink_op("/s", 7, "t"),
        file_op("/hard", 8),
    ]
}

fn run_random(seed: u64, steps: usize) -> (Hash, usize, usize) {
    let mut a = State::new();
    let mut b = State::new();
    for op in random_setup() {
        let _ = must_apply(&mut a, &op);
        let _ = must_apply(&mut b, &op);
    }
    let mut rng = Lcg::new(seed);
    let mut ino: Ino = 100;
    let mut applied = 0usize;
    let mut rejected = 0usize;
    for _ in 0..steps {
        let op = random_op(&mut rng, &mut ino);
        let plan_a = a.plan(&op);
        let plan_b = b.plan(&op);
        assert_eq!(plan_a.is_apply(), plan_b.is_apply(), "plan disagreement");
        if plan_a.is_apply() {
            match a.apply(&op) {
                Ok(()) => {}
                Err(reject) => panic!("apply a failed: {reject}"),
            }
            match b.apply(&op) {
                Ok(()) => {}
                Err(reject) => panic!("apply b failed: {reject}"),
            }
            applied += 1;
        } else {
            rejected += 1;
        }
        match a.check_invariants() {
            Ok(()) => {}
            Err(why) => panic!("invariants a: {why}"),
        }
        match b.check_invariants() {
            Ok(()) => {}
            Err(why) => panic!("invariants b: {why}"),
        }
        assert_eq!(a.digest(), b.digest(), "digest mismatch");
    }
    (a.digest(), applied, rejected)
}

#[test]
fn u_state_random_determinism() {
    let (first, applied, rejected) = run_random(0xC0FF_EE00_1234_5678, 400);
    let (second, applied_again, rejected_again) = run_random(0xC0FF_EE00_1234_5678, 400);
    assert_eq!(
        (first, applied, rejected),
        (second, applied_again, rejected_again)
    );
    assert!(applied > 0, "no operation applied");
    assert!(rejected > 0, "no operation rejected");
}
