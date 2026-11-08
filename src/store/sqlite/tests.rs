//! Unit tests for the shared SQLite store.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use rusqlite::Connection;

use super::*;

fn temp_db(role: Role) -> (tempfile::TempDir, Db) {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(dir.path().join("state.db"), role).unwrap();
    (dir, db)
}

fn ino(byte: u8) -> [u8; 16] {
    [byte; 16]
}

fn dir_object(ino: [u8; 16], mode: u32, nlink: u32) -> Object {
    Object {
        ino,
        kind: ObjectKind::Dir,
        mode,
        uid: 0,
        gid: 0,
        mtime_ns: 1_000,
        size: 0,
        file_root: file_root(ObjectKind::Dir, None, &[]),
        block_count: 0,
        target: None,
        nlink,
        deleted: false,
        created_seq: 0,
        updated_seq: 0,
    }
}

fn file_object(ino: [u8; 16], size: u64, chunks: &[ChunkRef], nlink: u32) -> Object {
    Object {
        ino,
        kind: ObjectKind::File,
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime_ns: 2_000,
        size,
        file_root: file_root(ObjectKind::File, None, chunks),
        block_count: chunks.len() as u32,
        target: None,
        nlink,
        deleted: false,
        created_seq: 0,
        updated_seq: 0,
    }
}

fn symlink_object(ino: [u8; 16], target: &[u8], mode: u32) -> Object {
    Object {
        ino,
        kind: ObjectKind::Symlink,
        mode,
        uid: 0,
        gid: 0,
        mtime_ns: 3_000,
        size: target.len() as u64,
        file_root: file_root(ObjectKind::Symlink, Some(target), &[]),
        block_count: 0,
        target: Some(target.to_vec()),
        nlink: 1,
        deleted: false,
        created_seq: 0,
        updated_seq: 0,
    }
}

fn other_kind(kind: EventKind) -> EventKind {
    if kind == EventKind::Write {
        EventKind::Truncate
    } else {
        EventKind::Write
    }
}

#[test]
fn u_store_sqlite_open_migrates_and_seeds_root() {
    let (_dir, db) = temp_db(Role::Server);
    assert_eq!(db.schema_version().unwrap(), SCHEMA_VERSION);

    let read = db.read().unwrap();
    let root = read.object(ROOT_INO).unwrap().expect("root row");
    assert_eq!(root.kind, ObjectKind::Dir);
    assert_eq!(root.mode, ROOT_MODE);
    assert_eq!(root.nlink, ROOT_NLINK);
    assert_eq!(root.size, 0);
    assert_eq!(root.file_root, file_root(ObjectKind::Dir, None, &[]));
    assert!(!root.deleted);
    assert!(read.children(ROOT_INO).unwrap().is_empty());

    assert_eq!(read.meta_i64(keys::EPOCH).unwrap(), DEFAULT_EPOCH);
    assert_eq!(read.meta_i64(keys::SEQ).unwrap(), 0);
    assert_eq!(
        read.meta_i64(keys::CHUNK_SIZE).unwrap(),
        i64::from(CHUNK_BYTES)
    );
    assert_eq!(read.state_hash().unwrap(), db.state_hash().unwrap());
}

#[test]
fn u_store_sqlite_root_state_hash_is_stable() {
    let (_dir, db) = temp_db(Role::Server);
    assert_eq!(
        hex::encode(db.state_hash().unwrap()),
        "b2960c15e9dafbccdab5ca40ed89ed0d633d4d70b6dab84468ceb102e91aa304"
    );
}

#[test]
fn u_store_sqlite_rejects_future_schema() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("future.db");
    {
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", 99).unwrap();
    }
    let err = Db::open(&path, Role::Server).unwrap_err();
    assert!(matches!(
        err,
        StoreError::UnsupportedSchema {
            found: 99,
            supported: SCHEMA_VERSION
        }
    ));
}

#[test]
fn u_store_sqlite_rejects_role_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    drop(Db::open(&path, Role::Server).unwrap());
    let err = Db::open(&path, Role::Client).unwrap_err();
    assert!(matches!(
        err,
        StoreError::RoleMismatch {
            stored: Role::Server,
            requested: Role::Client
        }
    ));
}

#[test]
fn u_store_sqlite_reopen_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    let before;
    {
        let mut db = Db::open(&path, Role::Server).unwrap();
        let tx = db.write().unwrap();
        tx.put_object(&dir_object(ino(2), 0o755, 2)).unwrap();
        tx.put_name(ROOT_INO, "a", ino(2), "/a").unwrap();
        tx.commit().unwrap();
        before = db.state_hash().unwrap();
    }

    let db = Db::open(&path, Role::Server).unwrap();
    assert_eq!(db.state_hash().unwrap(), before);
    let read = db.read().unwrap();
    assert!(read.object(ino(2)).unwrap().is_some());
    assert_eq!(read.children(ROOT_INO).unwrap().len(), 1);
    assert_eq!(read.meta_i64(keys::EPOCH).unwrap(), DEFAULT_EPOCH);
}

#[test]
fn u_store_sqlite_checkpoint_wal_succeeds() {
    let (_dir, mut db) = temp_db(Role::Server);
    {
        let tx = db.write().unwrap();
        tx.set_meta_i64("probe", 1).unwrap();
        tx.commit().unwrap();
    }
    db.checkpoint_wal().unwrap();
    assert_eq!(db.read().unwrap().meta_i64("probe").unwrap(), 1);
}

#[test]
fn u_store_sqlite_raw_conn_shares_the_transaction() {
    let (_dir, mut db) = temp_db(Role::Client);
    let op = ino(1);

    {
        let tx = db.write().unwrap();
        tx.conn()
            .execute(
                "INSERT INTO outbox
                   (op_id, kind, path, path2, ino, payload, undo, state, attempts, created_at)
                 VALUES (?1, 'create_file', '/a', NULL, ?2, X'00', NULL, 'pending', 0, 1)",
                rusqlite::params![op.as_slice(), ino(2).as_slice()],
            )
            .unwrap();
        let count: i64 = tx
            .conn()
            .query_row("SELECT COUNT(*) FROM outbox", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
        // Dropped without commit: the raw insert rolls back with the rest.
    }
    let count: i64 = db
        .read()
        .unwrap()
        .conn()
        .query_row("SELECT COUNT(*) FROM outbox", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);

    {
        let tx = db.write().unwrap();
        tx.conn()
            .execute(
                "INSERT INTO fuse_inos (ino, fuse_ino) VALUES (?1, 2)",
                [ino(2).as_slice()],
            )
            .unwrap();
        tx.commit().unwrap();
    }
    let read = db.read().unwrap();
    let fuse_ino: i64 = read
        .conn()
        .query_row(
            "SELECT fuse_ino FROM fuse_inos WHERE ino = ?1",
            [ino(2).as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fuse_ino, 2);
}

#[test]
fn u_store_sqlite_write_tx_commits_and_rolls_back() {
    let (_dir, mut db) = temp_db(Role::Server);

    {
        let tx = db.write().unwrap();
        tx.set_meta_i64("probe", 7).unwrap();
        // Dropped without commit: must roll back.
    }
    assert!(db.read().unwrap().get_meta("probe").unwrap().is_none());

    {
        let tx = db.write().unwrap();
        tx.set_meta_i64("probe", 7).unwrap();
        tx.put_object(&dir_object(ino(3), 0o755, 2)).unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(db.read().unwrap().meta_i64("probe").unwrap(), 7);
    assert!(db.read().unwrap().object(ino(3)).unwrap().is_some());

    {
        let tx = db.write().unwrap();
        tx.put_object(&dir_object(ino(4), 0o755, 2)).unwrap();
        // Dropped without commit.
    }
    assert!(db.read().unwrap().object(ino(4)).unwrap().is_none());
}

#[test]
fn u_store_sqlite_seq_is_atomic_and_unique() {
    let (_dir, mut db) = temp_db(Role::Server);

    {
        let tx = db.write().unwrap();
        assert_eq!(tx.bump_seq().unwrap(), 1);
        assert_eq!(tx.bump_seq().unwrap(), 2);
        tx.commit().unwrap();
    }

    {
        let tx = db.write().unwrap();
        assert_eq!(tx.bump_seq().unwrap(), 3);
        // Rolled back: the next transaction must reuse 3.
    }

    {
        let tx = db.write().unwrap();
        assert_eq!(tx.bump_seq().unwrap(), 3);
        let inserted = tx
            .insert_event(3, EventDraft::sync_ctrl(ino(3), 1))
            .unwrap();
        assert_eq!(inserted.seq, 3);
        assert!(matches!(
            tx.insert_event(3, EventDraft::sync_ctrl(ino(4), 2)),
            Err(StoreError::DuplicateSeq { seq: 3 })
        ));
        tx.commit().unwrap();
    }

    {
        let tx = db.write().unwrap();
        assert_eq!(tx.bump_seq().unwrap(), 4);
        tx.commit().unwrap();
    }

    let read = db.read().unwrap();
    assert_eq!(read.meta_i64(keys::SEQ).unwrap(), 4);
    assert_eq!(read.event_count().unwrap(), 1);
}

#[test]
fn u_store_sqlite_events_from_pages_in_order() {
    let (_dir, mut db) = temp_db(Role::Server);
    {
        let tx = db.write().unwrap();
        for seq in 1..=5 {
            assert_eq!(tx.bump_seq().unwrap(), seq);
            tx.insert_event(seq, EventDraft::sync_ctrl(ino(seq as u8), seq))
                .unwrap();
        }
        tx.commit().unwrap();
    }

    let read = db.read().unwrap();
    let first = read.events_from(1, 0, 2).unwrap();
    assert_eq!(
        first.iter().map(|event| event.seq).collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(
        first[0].decode().unwrap(),
        EventPayload::SyncCtrl { code: 1 }
    );

    let second = read.events_from(1, 2, 2).unwrap();
    assert_eq!(
        second.iter().map(|event| event.seq).collect::<Vec<_>>(),
        vec![3, 4]
    );

    let third = read.events_from(1, 4, 2).unwrap();
    assert_eq!(
        third.iter().map(|event| event.seq).collect::<Vec<_>>(),
        vec![5]
    );

    assert!(read.events_from(1, 5, 2).unwrap().is_empty());
    assert!(read.events_from(1, 0, 0).unwrap().is_empty());
    assert_eq!(read.events_from(1, 0, u32::MAX).unwrap().len(), 5);

    assert!(matches!(
        read.events_from(2, 0, 2),
        Err(StoreError::StaleEpoch {
            requested: 2,
            current: 1
        })
    ));
}

#[test]
fn u_store_sqlite_op_id_is_idempotent() {
    let (_dir, mut db) = temp_db(Role::Server);
    let op = ino(9);

    {
        let tx = db.write().unwrap();
        assert_eq!(tx.bump_seq().unwrap(), 1);
        tx.insert_event(1, EventDraft::sync_ctrl(op, 1)).unwrap();
        tx.commit().unwrap();
    }

    {
        let tx = db.write().unwrap();
        assert_eq!(tx.bump_seq().unwrap(), 2);
        let err = tx
            .insert_event(2, EventDraft::sync_ctrl(op, 2))
            .unwrap_err();
        assert!(matches!(
            err,
            StoreError::DuplicateOp {
                op_id,
                existing: 1
            } if op_id == op
        ));
        // Rolled back: seq returns to 1.
    }
    assert_eq!(db.read().unwrap().meta_i64(keys::SEQ).unwrap(), 1);

    {
        let tx = db.write().unwrap();
        assert_eq!(tx.bump_seq().unwrap(), 2);
        assert!(matches!(
            tx.insert_event(2, EventDraft::sync_ctrl(op, 3)),
            Err(StoreError::DuplicateOp { .. })
        ));
        tx.insert_event(2, EventDraft::sync_ctrl(ino(10), 4))
            .unwrap();
        tx.commit().unwrap();
    }

    let read = db.read().unwrap();
    assert_eq!(read.event_count().unwrap(), 2);
    assert_eq!(read.meta_i64(keys::SEQ).unwrap(), 2);
}

#[test]
fn u_store_sqlite_state_hash_is_order_independent() {
    fn build(reverse: bool) -> [u8; 32] {
        let (_dir, mut db) = temp_db(Role::Server);
        let a = ino(2);
        let f = ino(3);
        let b = ino(4);
        let data = b"data";
        let hash = chunk_hash(data);
        let chunk = ChunkRef {
            chunk_no: 0,
            hash,
            offset: 0,
            len: 4,
        };

        let tx = db.write().unwrap();
        tx.put_chunk(hash, 4, Some(data)).unwrap();
        let mut objects = vec![
            dir_object(a, 0o755, 2),
            file_object(f, 4, std::slice::from_ref(&chunk), 1),
            dir_object(b, 0o755, 2),
        ];
        if reverse {
            objects.reverse();
        }
        for object in &objects {
            tx.put_object(object).unwrap();
        }
        let mut names = vec![
            (ROOT_INO, "a", a, "/a"),
            (a, "f", f, "/a/f"),
            (ROOT_INO, "b", b, "/b"),
        ];
        if reverse {
            names.reverse();
        }
        for (parent, name, target, path) in names {
            tx.put_name(parent, name, target, path).unwrap();
        }
        tx.set_object_chunks(f, std::slice::from_ref(&chunk))
            .unwrap();
        tx.commit().unwrap();

        db.state_hash().unwrap()
    }

    assert_eq!(build(false), build(true));
}

#[test]
fn u_store_sqlite_state_hash_tracks_tree_changes() {
    let (_dir, mut db) = temp_db(Role::Server);
    let empty = db.state_hash().unwrap();

    let a = ino(2);
    let f = ino(3);
    let data = b"data";
    let hash = chunk_hash(data);
    let chunk = ChunkRef {
        chunk_no: 0,
        hash,
        offset: 0,
        len: 4,
    };
    {
        let tx = db.write().unwrap();
        tx.put_chunk(hash, 4, Some(data)).unwrap();
        tx.put_object(&dir_object(a, 0o755, 2)).unwrap();
        tx.put_name(ROOT_INO, "a", a, "/a").unwrap();
        tx.put_object(&file_object(f, 4, std::slice::from_ref(&chunk), 1))
            .unwrap();
        tx.put_name(a, "f", f, "/a/f").unwrap();
        tx.set_object_chunks(f, std::slice::from_ref(&chunk))
            .unwrap();
        tx.commit().unwrap();
    }
    let with_file = db.state_hash().unwrap();
    assert_ne!(empty, with_file);

    {
        let tx = db.write().unwrap();
        tx.delete_name(a, "f").unwrap();
        tx.put_name(a, "g", f, "/a/g").unwrap();
        tx.commit().unwrap();
    }
    let renamed = db.state_hash().unwrap();
    assert_ne!(with_file, renamed);

    let mut changed = db.read().unwrap().object(f).unwrap().unwrap();
    changed.mode = 0o600;
    {
        let tx = db.write().unwrap();
        tx.put_object(&changed).unwrap();
        tx.commit().unwrap();
    }
    assert_ne!(renamed, db.state_hash().unwrap());
}

#[test]
fn u_store_sqlite_compact_preserves_state_hash() {
    let (_dir, mut db) = temp_db(Role::Server);

    let dir_ino = ino(2);
    let file_ino = ino(3);
    let link_ino = ino(4);
    let hard_ino = ino(5);

    let data0 = vec![0xABu8; CHUNK_BYTES as usize];
    let data1 = b"tail".to_vec();
    let hard_data = b"abc";
    let chunk0 = chunk_hash(&data0);
    let chunk1 = chunk_hash(&data1);
    let hard_chunk = chunk_hash(hard_data);
    let refs = vec![
        ChunkRef {
            chunk_no: 0,
            hash: chunk0,
            offset: 0,
            len: CHUNK_BYTES,
        },
        ChunkRef {
            chunk_no: 1,
            hash: chunk1,
            offset: u64::from(CHUNK_BYTES),
            len: data1.len() as u32,
        },
    ];
    let hard_ref = ChunkRef {
        chunk_no: 0,
        hash: hard_chunk,
        offset: 0,
        len: 3,
    };
    let file_size = u64::from(CHUNK_BYTES) + data1.len() as u64;

    {
        let tx = db.write().unwrap();
        tx.put_chunk(chunk0, CHUNK_BYTES, Some(&data0)).unwrap();
        tx.put_chunk(chunk1, data1.len() as u32, Some(&data1))
            .unwrap();
        tx.put_chunk(hard_chunk, 3, Some(hard_data)).unwrap();

        tx.put_object(&dir_object(dir_ino, 0o755, 3)).unwrap();
        tx.put_name(ROOT_INO, "dir", dir_ino, "/dir").unwrap();

        tx.put_object(&file_object(file_ino, file_size, &refs, 1))
            .unwrap();
        tx.put_name(dir_ino, "file", file_ino, "/dir/file").unwrap();
        tx.set_object_chunks(file_ino, &refs).unwrap();

        tx.put_object(&symlink_object(link_ino, b"file", 0o777))
            .unwrap();
        tx.put_name(dir_ino, "link", link_ino, "/dir/link").unwrap();

        tx.put_object(&file_object(
            hard_ino,
            3,
            std::slice::from_ref(&hard_ref),
            2,
        ))
        .unwrap();
        tx.put_name(ROOT_INO, "hard", hard_ino, "/hard").unwrap();
        tx.put_name(dir_ino, "hard2", hard_ino, "/dir/hard2")
            .unwrap();
        tx.set_object_chunks(hard_ino, std::slice::from_ref(&hard_ref))
            .unwrap();
        tx.commit().unwrap();
    }

    let before = db.state_hash().unwrap();
    let report = db.compact().unwrap();
    assert_eq!(report.epoch, DEFAULT_EPOCH + 1);
    assert_eq!(report.objects, 5);
    assert_eq!(report.links, 1);
    assert!(report.events >= report.objects * 2);

    {
        let read = db.read().unwrap();
        assert_eq!(read.meta_i64(keys::EPOCH).unwrap(), 2);
        assert_eq!(read.meta_i64(keys::SEQ).unwrap(), report.events as i64);
        assert_eq!(read.event_count().unwrap(), report.events as i64);
        assert_eq!(read.state_hash().unwrap(), before);

        let events = read.events_from(2, 0, u32::MAX).unwrap();
        assert_eq!(events.len() as u64, report.events);
        assert!(events.windows(2).all(|pair| pair[0].seq < pair[1].seq));
        assert_eq!(events[0].path.as_deref(), Some("/"));

        let kinds: Vec<EventKind> = events.iter().map(|event| event.kind).collect();
        for expected in [
            EventKind::CreateDir,
            EventKind::CreateFile,
            EventKind::Symlink,
            EventKind::Write,
            EventKind::Setattr,
            EventKind::Link,
        ] {
            assert!(kinds.contains(&expected), "missing {expected}");
        }
        for event in &events {
            event.decode().unwrap();
        }

        // Each content chunk is referenced by object_chunks and by the
        // regenerated write event.
        assert_eq!(read.chunk(chunk0).unwrap().unwrap().refcount, 2);
        assert_eq!(read.chunk(chunk1).unwrap().unwrap().refcount, 2);
        assert_eq!(read.chunk(hard_chunk).unwrap().unwrap().refcount, 2);
    }

    let second = db.compact().unwrap();
    assert_eq!(second.epoch, 3);
    assert_eq!(db.state_hash().unwrap(), before);
}

#[test]
fn u_store_sqlite_compact_rejects_client_role() {
    let (_dir, mut db) = temp_db(Role::Client);
    assert!(matches!(
        db.compact(),
        Err(StoreError::WrongRole {
            operation: "compact",
            ..
        })
    ));
}

#[test]
fn u_store_sqlite_gc_reclaims_only_unreferenced_chunks() {
    let (_dir, mut db) = temp_db(Role::Server);
    let live_data = b"live";
    let event_data = b"event-only";
    let orphan_data = b"orphan";
    let live = ChunkRef {
        chunk_no: 0,
        hash: chunk_hash(live_data),
        offset: 0,
        len: 4,
    };
    let event_only = ChunkRef {
        chunk_no: 0,
        hash: chunk_hash(event_data),
        offset: 0,
        len: 10,
    };
    let orphan_hash = chunk_hash(orphan_data);

    let file = file_object(ino(2), 4, std::slice::from_ref(&live), 1);
    {
        let tx = db.write().unwrap();
        tx.put_chunk(live.hash, 4, Some(live_data)).unwrap();
        tx.put_chunk(event_only.hash, 10, Some(event_data)).unwrap();
        tx.put_chunk(orphan_hash, 6, Some(orphan_data)).unwrap();
        tx.put_object(&file).unwrap();
        tx.put_name(ROOT_INO, "f", ino(2), "/f").unwrap();
        tx.set_object_chunks(ino(2), std::slice::from_ref(&live))
            .unwrap();
        let seq = tx.bump_seq().unwrap();
        tx.insert_event(
            seq,
            EventDraft {
                epoch: None,
                op_id: Some(ino(9)),
                session_id: None,
                path: Some("/g".to_owned()),
                path2: None,
                payload: EventPayload::Write {
                    ino: ino(2),
                    offset: 0,
                    len: 10,
                    size: 10,
                    file_root: file_root(ObjectKind::File, None, std::slice::from_ref(&event_only)),
                    mtime_ns: 2_000,
                    chunks: vec![event_only.clone()],
                },
                result: "ok".to_owned(),
                created_at: 1,
            },
        )
        .unwrap();
        tx.commit().unwrap();
    }
    {
        let read = db.read().unwrap();
        assert_eq!(read.chunk(event_only.hash).unwrap().unwrap().refcount, 1);
        assert_eq!(read.chunk(orphan_hash).unwrap().unwrap().refcount, 0);
    }

    db.compact().unwrap();
    let now = now_secs();

    // Inside the retention window nothing is deleted.
    {
        let tx = db.write().unwrap();
        let report = tx.gc_orphan_chunks(now - 3_600).unwrap();
        assert_eq!(report.orphans, 2);
        assert_eq!(report.deleted, 0);
        tx.commit().unwrap();
    }
    {
        let read = db.read().unwrap();
        assert!(read.chunk(event_only.hash).unwrap().is_some());
        assert!(read.chunk(orphan_hash).unwrap().is_some());
    }

    // An uncommitted collection rolls back with its transaction.
    {
        let tx = db.write().unwrap();
        tx.gc_orphan_chunks(now).unwrap();
    }
    {
        let read = db.read().unwrap();
        assert!(read.chunk(orphan_hash).unwrap().is_some());
    }

    let report = {
        let tx = db.write().unwrap();
        let report = tx.gc_orphan_chunks(now).unwrap();
        tx.commit().unwrap();
        report
    };
    assert_eq!(report.orphans, 2);
    assert_eq!(report.deleted, 2);
    assert_eq!(report.freed_bytes, 16);

    let read = db.read().unwrap();
    assert!(read.chunk(event_only.hash).unwrap().is_none());
    assert!(read.chunk(orphan_hash).unwrap().is_none());
    let live = read.chunk(live.hash).unwrap().expect("live chunk kept");
    assert_eq!(live.refcount, 2);
}

#[test]
fn u_store_sqlite_client_watermark_refreshes_state_hash() {
    let (_dir, mut db) = temp_db(Role::Client);
    let before = db.read().unwrap().meta_blob(keys::STATE_HASH).unwrap();

    // A plain local mutation does not pay for a whole-tree digest.
    let data = b"hello";
    let chunk = ChunkRef {
        chunk_no: 0,
        hash: chunk_hash(data),
        offset: 0,
        len: 5,
    };
    {
        let tx = db.write().unwrap();
        tx.put_chunk(chunk.hash, 5, Some(data)).unwrap();
        tx.put_object(&file_object(ino(2), 5, std::slice::from_ref(&chunk), 1))
            .unwrap();
        tx.put_name(ROOT_INO, "f", ino(2), "/f").unwrap();
        tx.set_object_chunks(ino(2), std::slice::from_ref(&chunk))
            .unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(
        db.read().unwrap().meta_blob(keys::STATE_HASH).unwrap(),
        before
    );
    let tree = db.state_hash().unwrap();
    assert_ne!(tree.to_vec(), before);

    // A replay batch, checkpoint or fast-forward writes a watermark; the
    // commit refreshes the digest once for the whole transaction.
    {
        let tx = db.write().unwrap();
        tx.set_meta_i64(keys::APPLIED_SEQ, 1).unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(
        db.read().unwrap().meta_blob(keys::STATE_HASH).unwrap(),
        tree.to_vec()
    );
}

#[test]
fn u_store_sqlite_payload_roundtrips_every_kind() {
    let chunk = ChunkRef {
        chunk_no: 0,
        hash: [1; 32],
        offset: 0,
        len: 10,
    };
    let payloads = vec![
        EventPayload::CreateFile {
            ino: ino(1),
            mode: 0o644,
            uid: 1,
            gid: 2,
            mtime_ns: 3,
            file_root: [2; 32],
        },
        EventPayload::CreateDir {
            ino: ino(2),
            mode: 0o755,
            uid: 1,
            gid: 2,
            mtime_ns: 3,
            file_root: [3; 32],
        },
        EventPayload::Symlink {
            ino: ino(3),
            mode: 0o777,
            uid: 1,
            gid: 2,
            mtime_ns: 3,
            target: b"target".to_vec(),
            file_root: [4; 32],
        },
        EventPayload::Write {
            ino: ino(4),
            offset: 5,
            len: 10,
            size: 15,
            file_root: [5; 32],
            mtime_ns: 6,
            chunks: vec![chunk.clone()],
        },
        EventPayload::Truncate {
            ino: ino(5),
            size: 12,
            file_root: [6; 32],
            mtime_ns: 7,
        },
        EventPayload::Setattr {
            ino: ino(6),
            mode: Some(0o600),
            uid: None,
            gid: Some(4),
            mtime_ns: Some(8),
            size: None,
        },
        EventPayload::Rename {
            ino: ino(7),
            mtime_ns: Some(9),
        },
        EventPayload::Unlink {
            ino: ino(8),
            mtime_ns: Some(10),
        },
        EventPayload::Rmdir {
            ino: ino(9),
            mtime_ns: Some(11),
        },
        EventPayload::Link {
            ino: ino(10),
            mtime_ns: Some(12),
        },
        EventPayload::Lock {
            ino: ino(11),
            start: 0,
            len: 10,
            exclusive: true,
        },
        EventPayload::Unlock {
            ino: ino(12),
            start: 0,
            len: 10,
        },
        EventPayload::Leave,
        EventPayload::SyncCtrl { code: 42 },
    ];

    for payload in payloads {
        let kind = payload.kind();
        let bytes = payload.encode().unwrap();
        assert_eq!(bytes[0], PAYLOAD_VERSION);
        assert_eq!(EventPayload::decode(kind, &bytes).unwrap(), payload);
        assert!(matches!(
            EventPayload::decode(other_kind(kind), &bytes),
            Err(StoreError::PayloadKindMismatch { .. })
        ));
    }
}

#[test]
fn u_store_sqlite_decodes_a_version_1_setattr_without_size() {
    let expected = EventPayload::Setattr {
        ino: ino(0x11),
        mode: Some(0o644),
        uid: Some(1000),
        gid: Some(1001),
        mtime_ns: Some(1_700_000_000_000_000_000),
        size: None,
    };
    assert_eq!(
        EventPayload::decode(EventKind::Setattr, &V1_SETATTR_BYTES).unwrap(),
        expected
    );

    // The fixed bytes are the current encoding of the same payload without
    // the appended size tag: version 2 stores the identical body.
    let mut current = expected.encode().unwrap();
    assert_eq!(current[0], PAYLOAD_VERSION);
    assert_eq!(current.pop(), Some(0), "size: None is one tag byte");
    current[0] = PAYLOAD_VERSION_V1;
    assert_eq!(current, V1_SETATTR_BYTES);
}

#[test]
fn u_store_sqlite_decodes_version_1_payloads_of_every_other_kind() {
    let payloads = vec![
        EventPayload::CreateFile {
            ino: ino(1),
            mode: 0o644,
            uid: 1,
            gid: 2,
            mtime_ns: 3,
            file_root: [2; 32],
        },
        EventPayload::CreateDir {
            ino: ino(2),
            mode: 0o755,
            uid: 1,
            gid: 2,
            mtime_ns: 3,
            file_root: [3; 32],
        },
        EventPayload::Write {
            ino: ino(4),
            offset: 5,
            len: 10,
            size: 15,
            file_root: [5; 32],
            mtime_ns: 6,
            chunks: vec![ChunkRef {
                chunk_no: 0,
                hash: [7; 32],
                offset: 0,
                len: 10,
            }],
        },
        EventPayload::Truncate {
            ino: ino(5),
            size: 12,
            file_root: [6; 32],
            mtime_ns: 7,
        },
        EventPayload::Rename {
            ino: ino(7),
            mtime_ns: None,
        },
        EventPayload::Unlink {
            ino: ino(8),
            mtime_ns: None,
        },
        EventPayload::Rmdir {
            ino: ino(9),
            mtime_ns: None,
        },
        EventPayload::Link {
            ino: ino(10),
            mtime_ns: None,
        },
        EventPayload::Lock {
            ino: ino(11),
            start: 0,
            len: 10,
            exclusive: true,
        },
        EventPayload::Unlock {
            ino: ino(12),
            start: 0,
            len: 10,
        },
        EventPayload::Leave,
        EventPayload::SyncCtrl { code: 42 },
    ];
    for payload in payloads {
        // Version 1 stored only the inode for these four kinds; version 3
        // appends the optional timestamp.
        let timestamped = matches!(
            payload,
            EventPayload::Rename { .. }
                | EventPayload::Unlink { .. }
                | EventPayload::Rmdir { .. }
                | EventPayload::Link { .. }
        );
        let mut bytes = payload.encode().unwrap();
        if timestamped {
            assert_eq!(bytes.pop(), Some(0), "None timestamp is one tag byte");
        }
        assert_eq!(bytes[0], PAYLOAD_VERSION);
        bytes[0] = PAYLOAD_VERSION_V1;
        assert_eq!(
            EventPayload::decode(payload.kind(), &bytes).unwrap(),
            payload,
            "{:?} keeps its version-1 layout",
            payload.kind()
        );
        if !timestamped {
            assert!(matches!(
                EventPayload::decode(other_kind(payload.kind()), &bytes),
                Err(StoreError::PayloadKindMismatch { .. })
            ));
        }
    }
}

#[test]
fn u_store_sqlite_setattr_size_roundtrips() {
    let payload = EventPayload::Setattr {
        ino: ino(6),
        mode: Some(0o600),
        uid: None,
        gid: Some(4),
        mtime_ns: Some(8),
        size: Some(4096),
    };
    let bytes = payload.encode().unwrap();
    assert_eq!(bytes[0], PAYLOAD_VERSION);
    assert_eq!(bytes[1], 5, "setattr keeps its frozen bincode tag");
    assert_eq!(
        EventPayload::decode(EventKind::Setattr, &bytes).unwrap(),
        payload
    );
}

#[test]
fn u_store_sqlite_payload_rejects_corrupt_bytes() {
    assert!(matches!(
        EventPayload::decode(EventKind::Leave, &[]),
        Err(StoreError::Codec(_))
    ));
    assert!(matches!(
        EventPayload::decode(EventKind::Leave, &[PAYLOAD_VERSION + 1, 0]),
        Err(StoreError::PayloadVersion { found, .. }) if found == PAYLOAD_VERSION + 1
    ));

    let bytes = EventPayload::SyncCtrl { code: 1 }.encode().unwrap();
    assert!(matches!(
        EventPayload::decode(EventKind::SyncCtrl, &bytes[..bytes.len() - 1]),
        Err(StoreError::Codec(_))
    ));

    let mut trailing = bytes;
    trailing.push(0);
    assert!(matches!(
        EventPayload::decode(EventKind::SyncCtrl, &trailing),
        Err(StoreError::Codec(_))
    ));
}

#[test]
fn u_store_sqlite_rejects_inconsistent_event_drafts() {
    let (_dir, mut db) = temp_db(Role::Server);
    let tx = db.write().unwrap();

    let missing_op = EventDraft {
        epoch: None,
        op_id: None,
        session_id: None,
        path: None,
        path2: None,
        payload: EventPayload::SyncCtrl { code: 1 },
        result: "ok".to_owned(),
        created_at: 0,
    };
    assert!(matches!(
        tx.insert_event(1, missing_op),
        Err(StoreError::InvalidEvent { .. })
    ));

    let rename_without_path2 = EventDraft::new(
        ino(1),
        EventPayload::Rename {
            ino: ino(2),
            mtime_ns: None,
        },
        "/a",
    );
    assert!(matches!(
        tx.insert_event(1, rename_without_path2),
        Err(StoreError::InvalidEvent { .. })
    ));

    let leave_with_path = EventDraft {
        path: Some("/a".to_owned()),
        ..EventDraft::leave(ino(2))
    };
    assert!(matches!(
        tx.insert_event(1, leave_with_path),
        Err(StoreError::InvalidEvent { .. })
    ));

    let lock_without_session = EventDraft::new(
        ino(3),
        EventPayload::Lock {
            ino: ino(2),
            start: 0,
            len: 0,
            exclusive: true,
        },
        "/a",
    );
    assert!(matches!(
        tx.insert_event(1, lock_without_session),
        Err(StoreError::InvalidEvent { .. })
    ));
}

#[test]
fn u_store_sqlite_rejects_stale_event_epoch() {
    let (_dir, mut db) = temp_db(Role::Server);
    let tx = db.write().unwrap();
    let err = tx
        .insert_event(1, EventDraft::sync_ctrl(ino(1), 1).with_epoch(2))
        .unwrap_err();
    assert!(matches!(
        err,
        StoreError::StaleEpoch {
            requested: 2,
            current: 1
        }
    ));
}

#[test]
fn u_store_sqlite_chunk_rules_are_enforced() {
    let data = b"hello";
    let hash = chunk_hash(data);

    let (_dir, mut server) = temp_db(Role::Server);
    {
        let tx = server.write().unwrap();
        assert!(matches!(
            tx.put_chunk(hash, 5, Some(b"other")),
            Err(StoreError::ChunkHashMismatch)
        ));
        assert!(matches!(
            tx.put_chunk(hash, 4, Some(data)),
            Err(StoreError::ChunkLengthMismatch { .. })
        ));
        assert!(matches!(
            tx.put_chunk(hash, 5, None),
            Err(StoreError::ChunkDataRequired { .. })
        ));
        tx.put_chunk(hash, 5, Some(data)).unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(
        server.read().unwrap().chunk(hash).unwrap().unwrap().data,
        Some(data.to_vec())
    );

    let (_dir2, mut client) = temp_db(Role::Client);
    {
        let tx = client.write().unwrap();
        tx.put_chunk(hash, 5, None).unwrap();
        tx.commit().unwrap();
    }
    assert!(
        client
            .read()
            .unwrap()
            .chunk(hash)
            .unwrap()
            .unwrap()
            .data
            .is_none()
    );
    {
        let tx = client.write().unwrap();
        tx.put_chunk(hash, 5, Some(data)).unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(
        client.read().unwrap().chunk(hash).unwrap().unwrap().data,
        Some(data.to_vec())
    );
}

#[test]
fn u_store_sqlite_object_chunks_are_contiguous_and_recounted() {
    let (_dir, mut db) = temp_db(Role::Server);
    let a_data = b"aaaa";
    let b_data = b"bbbb";
    let a = ChunkRef {
        chunk_no: 0,
        hash: chunk_hash(a_data),
        offset: 0,
        len: 4,
    };
    let b = ChunkRef {
        chunk_no: 1,
        hash: chunk_hash(b_data),
        offset: u64::from(CHUNK_BYTES),
        len: 4,
    };
    {
        let tx = db.write().unwrap();
        tx.put_chunk(a.hash, 4, Some(a_data)).unwrap();
        tx.put_chunk(b.hash, 4, Some(b_data)).unwrap();
        tx.put_object(&file_object(ino(2), 4, std::slice::from_ref(&a), 1))
            .unwrap();

        let gap = ChunkRef {
            chunk_no: 2,
            ..a.clone()
        };
        assert!(matches!(
            tx.set_object_chunks(ino(2), &[a.clone(), gap]),
            Err(StoreError::NonContiguousChunks { .. })
        ));

        let wrong_offset = ChunkRef {
            offset: 1,
            ..a.clone()
        };
        assert!(matches!(
            tx.set_object_chunks(ino(2), &[wrong_offset]),
            Err(StoreError::ChunkOffsetMismatch { .. })
        ));

        tx.set_object_chunks(ino(2), &[a.clone(), b.clone()])
            .unwrap();
        tx.commit().unwrap();
    }

    {
        let read = db.read().unwrap();
        assert_eq!(
            read.object_chunks(ino(2)).unwrap(),
            vec![a.clone(), b.clone()]
        );
        assert_eq!(read.chunk(a.hash).unwrap().unwrap().refcount, 1);
        assert_eq!(read.chunk(b.hash).unwrap().unwrap().refcount, 1);
    }

    {
        let tx = db.write().unwrap();
        tx.set_object_chunks(ino(2), std::slice::from_ref(&a))
            .unwrap();
        tx.commit().unwrap();
    }
    let read = db.read().unwrap();
    assert_eq!(read.chunk(a.hash).unwrap().unwrap().refcount, 1);
    assert_eq!(read.chunk(b.hash).unwrap().unwrap().refcount, 0);
}

#[test]
fn u_store_sqlite_foreign_keys_are_enforced() {
    let (_dir, mut db) = temp_db(Role::Server);
    let tx = db.write().unwrap();
    let err = tx
        .put_name(ino(9), "orphan", ino(9), "/orphan")
        .unwrap_err();
    assert!(matches!(err, StoreError::Sqlite(_)));
}

#[test]
fn u_store_sqlite_validates_names_and_paths() {
    let (_dir, mut db) = temp_db(Role::Server);
    let tx = db.write().unwrap();
    tx.put_object(&dir_object(ino(2), 0o755, 2)).unwrap();

    for bad in ["", ".", "..", "a/b", "a\0b"] {
        assert!(matches!(
            tx.put_name(ROOT_INO, bad, ino(2), "/a"),
            Err(StoreError::InvalidName(_))
        ));
    }
    for bad in ["a", "/", "/a\0b"] {
        assert!(matches!(
            tx.put_name(ROOT_INO, "a", ino(2), bad),
            Err(StoreError::InvalidPath(_))
        ));
    }
}

#[test]
fn u_store_sqlite_validates_object_rows() {
    let (_dir, mut db) = temp_db(Role::Server);
    let tx = db.write().unwrap();

    let mut symlink_without_target = dir_object(ino(2), 0o777, 1);
    symlink_without_target.kind = ObjectKind::Symlink;
    assert!(matches!(
        tx.put_object(&symlink_without_target),
        Err(StoreError::Corrupt(_))
    ));

    let mut regular_with_target = dir_object(ino(3), 0o644, 1);
    regular_with_target.kind = ObjectKind::File;
    regular_with_target.target = Some(b"x".to_vec());
    assert!(matches!(
        tx.put_object(&regular_with_target),
        Err(StoreError::Corrupt(_))
    ));

    let mut deleted_with_links = dir_object(ino(4), 0o755, 1);
    deleted_with_links.deleted = true;
    assert!(matches!(
        tx.put_object(&deleted_with_links),
        Err(StoreError::Corrupt(_))
    ));
}

#[test]
fn u_store_sqlite_client_rejects_server_operations() {
    let (_dir, mut db) = temp_db(Role::Client);
    {
        let tx = db.write().unwrap();
        assert!(matches!(
            tx.bump_seq(),
            Err(StoreError::WrongRole {
                operation: "bump_seq",
                ..
            })
        ));
        assert!(matches!(
            tx.record_op_id(ino(1), [2; 32], 1, 0),
            Err(StoreError::WrongRole {
                operation: "record_op_id",
                ..
            })
        ));
    }
    assert!(matches!(
        db.read().unwrap().op_id(ino(1)),
        Err(StoreError::WrongRole {
            operation: "op_id",
            ..
        })
    ));
}

#[test]
fn u_store_sqlite_server_records_op_ids() {
    let (_dir, mut db) = temp_db(Role::Server);
    let op = ino(5);
    let inserted;
    {
        let tx = db.write().unwrap();
        assert_eq!(tx.bump_seq().unwrap(), 1);
        inserted = tx.insert_event(1, EventDraft::sync_ctrl(op, 1)).unwrap();
        tx.record_op_id(op, inserted.payload_hash, 1, 100).unwrap();
        assert!(matches!(
            tx.record_op_id(op, inserted.payload_hash, 1, 100),
            Err(StoreError::DuplicateOp { existing: 1, .. })
        ));
        tx.commit().unwrap();
    }

    let row = db.read().unwrap().op_id(op).unwrap().unwrap();
    assert_eq!(row.first_seq, 1);
    assert_eq!(row.payload_hash, inserted.payload_hash);
    assert_eq!(row.seen_at, 100);
}
