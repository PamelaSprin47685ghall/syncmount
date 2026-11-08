//! Unit tests for the mm foundation: schema, sequences, base, manifest and
//! isolation from the 1.0 database.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use rusqlite::Connection;
use tempfile::TempDir;

use super::*;
use crate::store::sqlite::{
    CHUNK_BYTES as STORE_CHUNK_BYTES, ChunkRef, Db, ObjectKind, Role, chunk_hash,
    file_root as store_file_root,
};

const NAMESPACE: &str = "/private-mm";

fn temp_db(role: MmRole, namespace: &str) -> (TempDir, MmDb) {
    let dir = tempfile::tempdir().unwrap();
    let db = MmDb::open(dir.path().join("server-mm.db"), role, namespace).unwrap();
    (dir, db)
}

fn ino(byte: u8) -> Ino {
    [byte; 16]
}

fn attrs(mtime_ns: i64) -> DirAttrs {
    DirAttrs {
        mode: 0o644,
        uid: 1000,
        gid: 1000,
        mtime_ns,
    }
}

fn chunk_refs(data: &[u8]) -> Vec<ChunkRef> {
    if data.is_empty() {
        return Vec::new();
    }
    data.chunks(CHUNK_BYTES as usize)
        .enumerate()
        .map(|(index, bytes)| ChunkRef {
            chunk_no: index as u32,
            hash: chunk_hash(bytes),
            offset: index as u64 * u64::from(CHUNK_BYTES),
            len: bytes.len() as u32,
        })
        .collect()
}

fn file_record(ino: Ino, dir_ino: Ino, name: &str, data: &[u8]) -> FileRecord {
    let chunks = chunk_refs(data);
    FileRecord {
        ino,
        dir_ino,
        name: name.to_owned(),
        kind: EntryKind::File,
        attrs: attrs(1_000),
        size: data.len() as u64,
        file_root: base::file_root(EntryKind::File, None, &chunks),
        content_hash: Some(*blake3::hash(data).as_bytes()),
        target: None,
        version: 1,
        deleted: false,
        created_at_ms: 1,
        updated_at_ms: 1,
    }
}

fn dir_record(ino: Ino, path: &str, seq: u64, version: Hash) -> DirRecord {
    DirRecord {
        ino,
        path: path.to_owned(),
        base: MmBase::new(1, DirSeq::new(seq), version),
        phase: Phase::Ready,
        attrs: attrs(1),
        deleted: false,
        created_at_ms: 1,
        updated_at_ms: 1,
    }
}

fn symlink_entry(name: &str, ino: Ino, target: &[u8], op: EntryOp) -> ManifestEntry {
    ManifestEntry {
        name: name.to_owned(),
        ino,
        kind: EntryKind::Symlink,
        op,
        from_name: None,
        mode: 0o777,
        uid: 0,
        gid: 0,
        mtime_ns: 1,
        size: u64::try_from(target.len()).unwrap(),
        file_root: base::symlink_root(target),
        content_hash: None,
        target: Some(target.to_vec()),
    }
}

fn dir_entry(name: &str, ino: Ino, op: EntryOp) -> ManifestEntry {
    ManifestEntry {
        name: name.to_owned(),
        ino,
        kind: EntryKind::Dir,
        op,
        from_name: None,
        mode: 0o755,
        uid: 0,
        gid: 0,
        mtime_ns: 1,
        size: 0,
        file_root: base::dir_root(),
        content_hash: None,
        target: None,
    }
}

fn tables(path: &Path) -> Vec<String> {
    let conn = Connection::open(path).unwrap();
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .unwrap();
    let rows = stmt.query_map([], |row| row.get::<_, String>(0)).unwrap();
    rows.collect::<rusqlite::Result<Vec<_>>>().unwrap()
}

#[test]
fn schema_creates_tables_and_root() {
    let (_dir, db) = temp_db(MmRole::Server, NAMESPACE);
    assert_eq!(db.schema_version().unwrap(), schema::MM_SCHEMA_VERSION);
    assert_eq!(db.epoch().unwrap(), 1);
    assert_eq!(db.mm_seq().unwrap(), MmSeq::ZERO);

    let root = db.read().unwrap().dir(ROOT_INO).unwrap().unwrap();
    assert_eq!(root.path, "/");
    assert_eq!(root.base.dir_seq, DirSeq::new(1));
    assert_eq!(root.phase, Phase::Ready);
    assert_eq!(
        root.base.dir_version,
        base::dir_version(
            NAMESPACE,
            ROOT_INO,
            &DirAttrs {
                mode: ROOT_MODE,
                uid: 0,
                gid: 0,
                mtime_ns: 0,
            },
            &[]
        )
    );

    let version = db
        .read()
        .unwrap()
        .dir_version_record(ROOT_INO)
        .unwrap()
        .unwrap();
    assert_eq!(version.dir_seq, DirSeq::new(1));
    assert_eq!(version.snapshot_seq, MmSeq::ZERO);
    assert_eq!(version.dir_version, root.base.dir_version);
}

#[test]
fn schema_is_idempotent_and_rejects_wrong_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("server-mm.db");
    {
        let db = MmDb::open(&path, MmRole::Server, NAMESPACE).unwrap();
        assert_eq!(db.schema_version().unwrap(), 1);
    }
    {
        let db = MmDb::open(&path, MmRole::Server, NAMESPACE).unwrap();
        assert_eq!(db.schema_version().unwrap(), 1);
        assert_eq!(db.read().unwrap().dirs().unwrap().len(), 1);
    }
    let error = MmDb::open(&path, MmRole::Client, NAMESPACE).unwrap_err();
    assert!(matches!(error, MmError::RoleMismatch { .. }));
    let error = MmDb::open(&path, MmRole::Server, "/public-mm").unwrap_err();
    assert!(matches!(error, MmError::NamespaceMismatch { .. }));
}

#[test]
fn schema_rejects_a_future_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("future.db");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA user_version = 99;")
        .unwrap();
    drop(conn);

    let error = MmDb::open(&path, MmRole::Server, NAMESPACE).unwrap_err();
    match error {
        MmError::UnsupportedSchema { found, supported } => {
            assert_eq!(found, 99);
            assert_eq!(supported, schema::MM_SCHEMA_VERSION);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn pragmas_are_wal_foreign_keys_and_five_seconds() {
    let (_dir, db) = temp_db(MmRole::Server, NAMESPACE);
    let read = db.read().unwrap();
    let conn = read.conn();
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode.to_ascii_lowercase(), "wal");
    let foreign_keys: i64 = conn
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .unwrap();
    assert_eq!(foreign_keys, 1);
    let busy_timeout: i64 = conn
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        busy_timeout,
        i64::try_from(schema::BUSY_TIMEOUT_MS).unwrap()
    );
}

#[test]
fn mm_seq_advances_and_rolls_back() {
    let (_dir, mut db) = temp_db(MmRole::Server, NAMESPACE);
    {
        let tx = db.write().unwrap();
        assert_eq!(tx.next_mm_seq().unwrap(), MmSeq::new(1));
        assert_eq!(tx.next_mm_seq().unwrap(), MmSeq::new(2));
        tx.commit().unwrap();
    }
    assert_eq!(db.mm_seq().unwrap(), MmSeq::new(2));

    {
        let tx = db.write().unwrap();
        assert_eq!(tx.next_mm_seq().unwrap(), MmSeq::new(3));
        // Dropping the transaction rolls it back.
    }
    assert_eq!(db.mm_seq().unwrap(), MmSeq::new(2));
}

#[test]
fn epoch_moves_only_when_explicitly_set() {
    let (_dir, mut db) = temp_db(MmRole::Server, NAMESPACE);
    assert_eq!(db.epoch().unwrap(), 1);
    assert_eq!(db.mm_seq().unwrap(), MmSeq::ZERO);

    let tx = db.write().unwrap();
    tx.set_epoch(2).unwrap();
    tx.commit().unwrap();
    assert_eq!(db.epoch().unwrap(), 2);
    assert_eq!(db.mm_seq().unwrap(), MmSeq::ZERO);

    let tx = db.write().unwrap();
    assert!(matches!(tx.set_epoch(0), Err(MmError::Invalid(_))));
    tx.rollback();
    assert_eq!(db.epoch().unwrap(), 2);
}

#[test]
fn dir_seq_is_per_directory_and_independent_of_mm_seq() {
    let (_dir, mut db) = temp_db(MmRole::Server, NAMESPACE);
    let child = ino(7);
    let version = base::dir_version(NAMESPACE, child, &attrs(1), &[]);

    let tx = db.write().unwrap();
    assert_eq!(tx.next_mm_seq().unwrap(), MmSeq::new(1));
    tx.put_dir(&dir_record(child, "/sub", 1, version)).unwrap();
    assert_eq!(tx.dir_seq(child).unwrap(), Some(DirSeq::new(1)));
    assert_eq!(tx.dir_seq(ROOT_INO).unwrap(), Some(DirSeq::new(1)));
    assert_eq!(
        tx.dir_version_record(child).unwrap().unwrap().snapshot_seq,
        MmSeq::new(1)
    );

    assert_eq!(tx.bump_dir(child).unwrap(), DirSeq::new(2));
    assert_eq!(tx.dir_seq(child).unwrap(), Some(DirSeq::new(2)));
    assert_eq!(tx.dir_seq(ROOT_INO).unwrap(), Some(DirSeq::new(1)));
    assert_eq!(tx.dir(child).unwrap().unwrap().base.dir_seq, DirSeq::new(2));
    tx.commit().unwrap();

    assert_eq!(db.mm_seq().unwrap(), MmSeq::new(1));
    assert_eq!(
        db.read().unwrap().dir_seq(child).unwrap(),
        Some(DirSeq::new(2))
    );
}

#[test]
fn base_triple_round_trips_and_updates_both_tables() {
    let (_dir, mut db) = temp_db(MmRole::Server, NAMESPACE);
    let child = ino(9);
    let version = base::dir_version(NAMESPACE, child, &attrs(5), &[]);
    let tx = db.write().unwrap();
    tx.put_dir(&dir_record(child, "/sub", 1, version)).unwrap();
    tx.commit().unwrap();

    let new_base = MmBase::new(2, DirSeq::new(3), [0xAB; 32]);
    let tx = db.write().unwrap();
    tx.set_base(child, &new_base).unwrap();
    tx.commit().unwrap();

    let read = db.read().unwrap();
    assert_eq!(read.base(child).unwrap(), Some(new_base));
    assert_eq!(read.dir_version(child).unwrap(), Some([0xAB; 32]));
    assert_eq!(read.dir(child).unwrap().unwrap().base, new_base);
    assert_eq!(
        read.dir_version_record(child).unwrap().unwrap().dir_seq,
        DirSeq::new(3)
    );
}

#[test]
fn read_snapshot_does_not_see_an_uncommitted_sequence() {
    let (_dir, mut writer) = temp_db(MmRole::Server, NAMESPACE);
    let reader = MmDb::open(writer.path(), MmRole::Server, NAMESPACE).unwrap();
    assert_eq!(reader.read().unwrap().mm_seq().unwrap(), MmSeq::ZERO);

    let tx = writer.write().unwrap();
    assert_eq!(tx.next_mm_seq().unwrap(), MmSeq::new(1));
    assert_eq!(reader.read().unwrap().mm_seq().unwrap(), MmSeq::ZERO);
    tx.commit().unwrap();
    assert_eq!(reader.read().unwrap().mm_seq().unwrap(), MmSeq::new(1));
}

#[test]
fn file_root_matches_the_1_0_store() {
    let data = vec![0x5A; (CHUNK_BYTES as usize) * 2 + 17];
    let chunks = chunk_refs(&data);
    assert_eq!(
        base::file_root(EntryKind::File, None, &chunks),
        store_file_root(ObjectKind::File, None, &chunks)
    );
    assert_eq!(
        base::empty_file_root(),
        store_file_root(ObjectKind::File, None, &[])
    );
    assert_eq!(
        base::dir_root(),
        store_file_root(ObjectKind::Dir, None, &[])
    );
    assert_eq!(
        base::symlink_root(b"../target"),
        store_file_root(ObjectKind::Symlink, Some(b"../target"), &[])
    );
    assert_eq!(STORE_CHUNK_BYTES, CHUNK_BYTES);
}

#[test]
fn dir_version_is_order_independent_and_ignores_transport_fields() {
    let first = file_record(ino(1), ROOT_INO, "a", b"alpha");
    let second = file_record(ino(2), ROOT_INO, "b", b"beta");
    let entries = vec![
        first.manifest_entry(EntryOp::Keep),
        second.manifest_entry(EntryOp::Put),
    ];
    let mut reversed = entries.clone();
    reversed.reverse();

    let one = base::dir_version(NAMESPACE, ROOT_INO, &attrs(10), &entries);
    let two = base::dir_version(NAMESPACE, ROOT_INO, &attrs(10), &reversed);
    assert_eq!(one, two);

    let mut changed_ops = entries.clone();
    changed_ops[0].op = EntryOp::Put;
    changed_ops[1].op = EntryOp::Delete;
    assert_eq!(
        one,
        base::dir_version(NAMESPACE, ROOT_INO, &attrs(10), &changed_ops)
    );

    let mut changed_hash = entries.clone();
    changed_hash[0].content_hash = Some([0xFF; 32]);
    assert_eq!(
        one,
        base::dir_version(NAMESPACE, ROOT_INO, &attrs(10), &changed_hash)
    );

    let mut changed_root = entries;
    changed_root[0].file_root = [0x11; 32];
    assert_ne!(
        one,
        base::dir_version(NAMESPACE, ROOT_INO, &attrs(10), &changed_root)
    );
    assert_ne!(
        one,
        base::dir_version(NAMESPACE, ino(3), &attrs(10), &changed_root)
    );
    assert_ne!(
        one,
        base::dir_version(NAMESPACE, ROOT_INO, &attrs(11), &changed_root)
    );
    assert_ne!(
        one,
        base::dir_version("/public-mm", ROOT_INO, &attrs(10), &changed_root)
    );
}

#[test]
fn manifest_is_canonical_and_complete() {
    let a = file_record(ino(1), ROOT_INO, "a", b"alpha");
    let b = symlink_entry("b", ino(2), b"target", EntryOp::Keep);
    let c = dir_entry("c", ino(3), EntryOp::Keep);
    let manifest =
        Manifest::new(vec![c.clone(), a.manifest_entry(EntryOp::Keep), b.clone()]).unwrap();
    assert_eq!(
        manifest
            .entries()
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "b", "c"]
    );

    let reordered = Manifest::new(vec![a.manifest_entry(EntryOp::Keep), b, c]).unwrap();
    assert_eq!(manifest.hash(), reordered.hash());

    let mut changed = manifest.clone().into_entries();
    changed[1].mode = 0o700;
    let changed = Manifest::new(changed).unwrap();
    assert_ne!(manifest.hash(), changed.hash());

    assert!(manifest.is_complete_for(["a", "b", "c"]));
    assert_eq!(manifest.missing_against(["a", "b", "c", "d"]), vec!["d"]);
    assert_eq!(manifest.missing_against(["c", "a", "d", "d"]), vec!["d"]);
    assert_eq!(manifest.unexpected_against(["a", "b"]), vec!["c"]);
    assert!(!manifest.is_complete_for(["a"]));
    assert!(!manifest.is_complete_for(["a", "b", "c", "d"]));
}

#[test]
fn manifest_rejects_duplicates_and_invalid_entries() {
    let a = file_record(ino(1), ROOT_INO, "a", b"alpha");
    let mut duplicate = a.manifest_entry(EntryOp::Put);
    duplicate.ino = ino(9);
    let duplicate = Manifest::new(vec![a.manifest_entry(EntryOp::Keep), duplicate]).unwrap_err();
    assert!(matches!(duplicate, ManifestError::DuplicateName(name) if name == "a"));

    let mut missing_hash = a.manifest_entry(EntryOp::Put);
    missing_hash.content_hash = None;
    assert!(matches!(
        Manifest::new(vec![missing_hash]).unwrap_err(),
        ManifestError::MissingContentHash(name) if name == "a"
    ));

    let mut bad_dir = dir_entry("d", ino(2), EntryOp::Keep);
    bad_dir.file_root = [0x22; 32];
    assert!(matches!(
        Manifest::new(vec![bad_dir]).unwrap_err(),
        ManifestError::InvalidFileRoot { .. }
    ));

    let mut bad_symlink = symlink_entry("s", ino(3), b"one", EntryOp::Keep);
    bad_symlink.target = Some(b"two".to_vec());
    assert!(matches!(
        Manifest::new(vec![bad_symlink]).unwrap_err(),
        ManifestError::InvalidFileRoot { .. }
    ));

    let mut bad_rename = a.manifest_entry(EntryOp::Rename);
    bad_rename.from_name = None;
    assert!(matches!(
        Manifest::new(vec![bad_rename]).unwrap_err(),
        ManifestError::MissingFromName(name) if name == "a"
    ));

    let mut duplicate_ino = file_record(ino(1), ROOT_INO, "b", b"beta");
    duplicate_ino.ino = a.ino;
    assert!(matches!(
        Manifest::new(vec![
            a.manifest_entry(EntryOp::Keep),
            duplicate_ino.manifest_entry(EntryOp::Keep)
        ])
        .unwrap_err(),
        ManifestError::DuplicateIno(value) if value == a.ino
    ));
}

#[test]
fn manifest_diff_emits_explicit_operations() {
    let keep = file_record(ino(1), ROOT_INO, "a", b"alpha");
    let renamed = file_record(ino(2), ROOT_INO, "c", b"beta");
    let removed = file_record(ino(4), ROOT_INO, "e", b"gone");
    let kept_dir = dir_entry("d", ino(3), EntryOp::Keep);
    let removed_dir = dir_entry("h", ino(8), EntryOp::Keep);
    let added = file_record(ino(5), ROOT_INO, "f", b"new");
    let added_dir = dir_entry("g", ino(6), EntryOp::Keep);

    let base = vec![
        keep.manifest_entry(EntryOp::Keep),
        ManifestEntry {
            name: "b".to_owned(),
            ..renamed.manifest_entry(EntryOp::Keep)
        },
        kept_dir,
        removed.manifest_entry(EntryOp::Keep),
        removed_dir,
    ];
    let current = vec![
        keep.manifest_entry(EntryOp::Keep),
        renamed.manifest_entry(EntryOp::Keep),
        dir_entry("d", ino(3), EntryOp::Keep),
        added.manifest_entry(EntryOp::Keep),
        added_dir,
    ];

    let manifest = Manifest::diff(&base, &current).unwrap();
    let ops: Vec<(&str, EntryOp)> = manifest
        .entries()
        .iter()
        .map(|entry| (entry.name.as_str(), entry.op))
        .collect();
    assert_eq!(
        ops,
        vec![
            ("a", EntryOp::Keep),
            ("c", EntryOp::Rename),
            ("d", EntryOp::Keep),
            ("e", EntryOp::Delete),
            ("f", EntryOp::Put),
            ("g", EntryOp::DirAdd),
            ("h", EntryOp::DirRemove),
        ]
    );
    let rename = manifest.get("c").unwrap();
    assert_eq!(rename.from_name.as_deref(), Some("b"));
}

#[test]
fn base_manifest_round_trips_through_the_database() {
    let (_dir, mut db) = temp_db(MmRole::Server, NAMESPACE);
    let file = file_record(ino(1), ROOT_INO, "a", b"alpha");
    let symlink = symlink_entry("s", ino(2), b"target", EntryOp::Keep);
    let dir = dir_entry("d", ino(3), EntryOp::Keep);
    let manifest = Manifest::new(vec![file.manifest_entry(EntryOp::Keep), symlink, dir]).unwrap();

    let tx = db.write().unwrap();
    tx.replace_base_manifest(ROOT_INO, &manifest).unwrap();
    tx.commit().unwrap();

    let read = db.read().unwrap();
    let stored = read.base_manifest(ROOT_INO).unwrap();
    assert_eq!(stored.len(), 3);
    assert_eq!(read.base_manifest_hash(ROOT_INO).unwrap(), manifest.hash());
    assert_eq!(
        stored
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "d", "s"]
    );
    assert!(stored.iter().all(|entry| entry.op == EntryOp::Keep));
    drop(read);

    // A base entry may omit `content_hash`; the snapshot still round-trips.
    let mut without_hash = file.manifest_entry(EntryOp::Keep);
    without_hash.content_hash = None;
    let sparse = Manifest::new(vec![without_hash]).unwrap();
    let tx = db.write().unwrap();
    tx.replace_base_manifest(ROOT_INO, &sparse).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        db.read().unwrap().base_manifest_hash(ROOT_INO).unwrap(),
        sparse.hash()
    );

    let tx = db.write().unwrap();
    tx.clear_base(ROOT_INO).unwrap();
    tx.commit().unwrap();
    assert!(
        db.read()
            .unwrap()
            .base_manifest(ROOT_INO)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn files_versions_and_chunks_round_trip() {
    let (_dir, mut db) = temp_db(MmRole::Server, NAMESPACE);
    let data = vec![0x33; (CHUNK_BYTES as usize) + 9];
    let file = file_record(ino(1), ROOT_INO, "a", &data);
    let chunks = chunk_refs(&data);

    let tx = db.write().unwrap();
    tx.put_file(&file).unwrap();
    for chunk in &chunks {
        let start = chunk.offset as usize;
        let end = start + chunk.len as usize;
        tx.put_chunk(chunk.hash, &data[start..end]).unwrap();
    }
    tx.put_version(&VersionRecord {
        ino: file.ino,
        version: 1,
        size: file.size,
        file_root: file.file_root,
        content_hash: file.content_hash.unwrap(),
        chunk_count: chunks.len() as u32,
        created_at_ms: 1,
    })
    .unwrap();
    tx.put_version_chunks(file.ino, 1, &chunks).unwrap();
    tx.commit().unwrap();

    let read = db.read().unwrap();
    assert_eq!(read.file(file.ino).unwrap().unwrap(), file);
    assert_eq!(read.files(ROOT_INO).unwrap(), vec![file.clone()]);
    assert_eq!(read.file_by_name(ROOT_INO, "a").unwrap().unwrap(), file);
    assert_eq!(read.version_chunks(file.ino, 1).unwrap(), chunks);
    assert_eq!(
        read.version(file.ino, 1).unwrap().unwrap().content_hash,
        file.content_hash.unwrap()
    );
    for chunk in &chunks {
        let start = chunk.offset as usize;
        let end = start + chunk.len as usize;
        assert_eq!(
            read.chunk(chunk.hash).unwrap().unwrap(),
            data[start..end].to_vec()
        );
    }

    // Replacing a version with the same chunks must not change refcounts.
    let tx = db.write().unwrap();
    tx.put_version_chunks(file.ino, 1, &chunks).unwrap();
    tx.commit().unwrap();
    for chunk in &chunks {
        let refcount: i64 = db
            .read()
            .unwrap()
            .conn()
            .query_row(
                "SELECT refcount FROM mm_chunks WHERE hash = ?1",
                [chunk.hash.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(refcount, 1);
    }

    let tx = db.write().unwrap();
    tx.put_version_chunks(file.ino, 1, &[]).unwrap();
    tx.commit().unwrap();
    for chunk in &chunks {
        let refcount: i64 = db
            .read()
            .unwrap()
            .conn()
            .query_row(
                "SELECT refcount FROM mm_chunks WHERE hash = ?1",
                [chunk.hash.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(refcount, 0);
    }
}

#[test]
fn foreign_keys_are_enforced() {
    let (_dir, mut db) = temp_db(MmRole::Server, NAMESPACE);
    let orphan = file_record(ino(1), ino(99), "a", b"alpha");
    let tx = db.write().unwrap();
    let error = tx.put_file(&orphan).unwrap_err();
    assert!(matches!(error, MmError::Sqlite(_)));
    tx.rollback();
}

#[test]
fn upload_lock_and_batch_rows_are_idempotent() {
    let (_dir, mut db) = temp_db(MmRole::Server, NAMESPACE);
    let batch_id = BatchId::from_bytes([1; 16]);
    let lock_id = LockId::from_bytes([2; 16]);
    let now = now_ms();
    let upload = UploadRecord {
        batch_id,
        lock_id,
        dir_path: "/".to_owned(),
        dir_ino: ROOT_INO,
        base_epoch: 1,
        base_seq: DirSeq::new(1),
        dir_version: [3; 32],
        manifest_hash: [4; 32],
        state: UploadState::Open,
        spool_path: "/tmp/spool".to_owned(),
        bytes_received: 0,
        created_at_ms: now,
        updated_at_ms: now,
        expires_at_ms: now + 60_000,
    };
    let lock = LockRecord {
        lock_id,
        dir_path: "/".to_owned(),
        dir_ino: ROOT_INO,
        owner_client: [5; 16],
        owner_session: [6; 16],
        base_epoch: 1,
        base_seq: DirSeq::new(1),
        batch_id: Some(batch_id),
        expires_at_ms: now + 60_000,
        created_at_ms: now,
        renewed_at_ms: now,
        progress_bytes: 0,
    };
    let batch = BatchRecord {
        batch_id,
        dir_path: "/".to_owned(),
        dir_ino: ROOT_INO,
        base_epoch: 1,
        base_seq: DirSeq::new(1),
        base_seq_after: DirSeq::new(2),
        snapshot_seq: MmSeq::new(1),
        dir_version_before: [7; 32],
        dir_version_after: [8; 32],
        manifest_hash: [4; 32],
        client_id: [9; 16],
        entry_count: 1,
        bytes: 5,
        committed_at_ms: now,
    };

    let tx = db.write().unwrap();
    tx.put_upload(&upload).unwrap();
    tx.put_lock(&lock).unwrap();
    assert!(tx.put_batch(&batch).unwrap());
    assert!(!tx.put_batch(&batch).unwrap());
    tx.commit().unwrap();

    let read = db.read().unwrap();
    assert_eq!(read.upload(batch_id).unwrap().unwrap(), upload);
    assert_eq!(read.uploads_for_lock(lock_id).unwrap(), vec![upload]);
    assert_eq!(read.lock(lock_id).unwrap().unwrap(), lock);
    assert_eq!(read.lock_for_dir("/").unwrap().unwrap(), lock);
    assert_eq!(read.batch(batch_id).unwrap().unwrap(), batch);
    assert_eq!(
        read.batch_by_snapshot(MmSeq::new(1)).unwrap().unwrap(),
        batch
    );
    drop(read);

    let tx = db.write().unwrap();
    tx.set_upload_state(batch_id, UploadState::Verified)
        .unwrap();
    tx.update_upload_progress(batch_id, 5, now + 120_000)
        .unwrap();
    tx.renew_lock(lock_id, now + 120_000, 5).unwrap();
    tx.commit().unwrap();
    let read = db.read().unwrap();
    let upload = read.upload(batch_id).unwrap().unwrap();
    assert_eq!(upload.state, UploadState::Verified);
    assert_eq!(upload.bytes_received, 5);
    let lock = read.lock(lock_id).unwrap().unwrap();
    assert_eq!(lock.progress_bytes, 5);
    drop(read);

    let tx = db.write().unwrap();
    assert_eq!(tx.delete_expired_locks(now + 60_000).unwrap(), vec![]);
    assert_eq!(
        tx.delete_expired_locks(now + 180_000).unwrap(),
        vec![lock_id]
    );
    assert!(!tx.delete_lock(lock_id).unwrap());
    assert!(tx.delete_upload(batch_id).unwrap());
    tx.commit().unwrap();
    let read = db.read().unwrap();
    assert!(read.lock(lock_id).unwrap().is_none());
    assert!(read.upload(batch_id).unwrap().is_none());
}

#[test]
fn mm_schema_does_not_touch_the_1_0_database() {
    let dir = tempfile::tempdir().unwrap();
    let one_path = dir.path().join("server.db");
    {
        let _db = Db::open(&one_path, Role::Server).unwrap();
    }
    let one_version: i64 = Connection::open(&one_path)
        .unwrap()
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    let one_tables = tables(&one_path);
    assert!(one_tables.iter().any(|name| name == "objects"));
    assert!(!one_tables.iter().any(|name| name.starts_with("mm_")));

    let mm_path = dir.path().join("server-mm.db");
    {
        let _db = MmDb::open(&mm_path, MmRole::Server, NAMESPACE).unwrap();
    }
    let mm_tables = tables(&mm_path);
    assert!(mm_tables.iter().any(|name| name == "mm_meta"));
    assert!(!mm_tables.iter().any(|name| name == "objects"));

    let reopened_version: i64 = Connection::open(&one_path)
        .unwrap()
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(reopened_version, one_version);
    assert_eq!(tables(&one_path), one_tables);

    // Neither end silently adopts the other's file.
    assert!(matches!(
        MmDb::open(&one_path, MmRole::Server, NAMESPACE).unwrap_err(),
        MmError::Sqlite(_)
    ));
    assert!(Db::open(&mm_path, Role::Server).is_err());
    assert_eq!(tables(&one_path), one_tables);
}

#[test]
fn canonical_vectors_are_stable() {
    // These values pin the on-disk/wire contract. A change here is a format
    // change, not a refactor: update the design and both ends together.
    let empty = Manifest::new(Vec::new()).unwrap();
    assert_eq!(
        hex::encode(empty.hash()),
        "ec2bd03bf86b935fa34d71ad7ebb049f1f10f87d343e521511d8f9e6625620cd"
    );

    let root = base::dir_version(
        NAMESPACE,
        ROOT_INO,
        &DirAttrs {
            mode: ROOT_MODE,
            uid: 0,
            gid: 0,
            mtime_ns: 0,
        },
        &[],
    );
    assert_eq!(
        hex::encode(root),
        "e0db574789fe80e038b4662680ee7be97f7522b666edfa8939b82013268904dc"
    );

    let file = file_record(ino(1), ROOT_INO, "a", b"alpha");
    let manifest = Manifest::new(vec![file.manifest_entry(EntryOp::Keep)]).unwrap();
    assert_eq!(
        hex::encode(manifest.hash()),
        "d2175b0d9d1a41aeb01e506bea8dd99d5053bec94552fc528e9398cb8cceef09"
    );
    assert_eq!(
        hex::encode(base::dir_version(
            NAMESPACE,
            ROOT_INO,
            &attrs(1_000),
            manifest.entries()
        )),
        "61951a196c42d09167a8e1ed4d794d8d94430aae4a5a66fc7abddb7f60fec004"
    );
}

#[test]
fn manifest_diff_replaces_a_recreated_name() {
    let base = file_record(ino(1), ROOT_INO, "a", b"alpha");
    let current = file_record(ino(2), ROOT_INO, "a", b"alpha");
    let manifest = Manifest::diff(
        &[base.manifest_entry(EntryOp::Keep)],
        &[current.manifest_entry(EntryOp::Keep)],
    )
    .unwrap();
    let entry = manifest.get("a").unwrap();
    assert_eq!(entry.op, EntryOp::Put);
    assert_eq!(entry.ino, ino(2));
    assert_eq!(entry.content_hash, current.content_hash);
}

#[test]
fn manifest_rejects_root_inode_and_negative_mtime() {
    let file = file_record(ino(1), ROOT_INO, "a", b"alpha");
    let mut root_ino = file.manifest_entry(EntryOp::Keep);
    root_ino.ino = ROOT_INO;
    assert!(matches!(
        Manifest::new(vec![root_ino]).unwrap_err(),
        ManifestError::RootInode(name) if name == "a"
    ));

    let mut negative = file.manifest_entry(EntryOp::Keep);
    negative.mtime_ns = -1;
    assert!(matches!(
        Manifest::new(vec![negative]).unwrap_err(),
        ManifestError::NegativeMtime(name) if name == "a"
    ));
}

#[test]
fn recreating_a_name_removes_the_old_inode_and_versions() {
    let (_dir, mut db) = temp_db(MmRole::Server, NAMESPACE);
    let old = file_record(ino(1), ROOT_INO, "a", b"old");
    let new = file_record(ino(2), ROOT_INO, "a", b"new");
    let tx = db.write().unwrap();
    tx.put_file(&old).unwrap();
    tx.put_version(&VersionRecord {
        ino: old.ino,
        version: 1,
        size: old.size,
        file_root: old.file_root,
        content_hash: old.content_hash.unwrap(),
        chunk_count: 0,
        created_at_ms: 1,
    })
    .unwrap();
    tx.put_file(&new).unwrap();
    tx.commit().unwrap();

    let read = db.read().unwrap();
    assert!(read.file(old.ino).unwrap().is_none());
    assert!(read.version(old.ino, 1).unwrap().is_none());
    assert_eq!(read.files(ROOT_INO).unwrap(), vec![new]);
}

#[test]
fn deleting_a_directory_cascades_its_rows() {
    let (_dir, mut db) = temp_db(MmRole::Server, NAMESPACE);
    let child = ino(3);
    let version = base::dir_version(NAMESPACE, child, &attrs(1), &[]);
    let nested = file_record(ino(4), child, "nested", b"data");
    let tx = db.write().unwrap();
    tx.put_dir(&dir_record(child, "/sub", 1, version)).unwrap();
    tx.put_file(&nested).unwrap();
    tx.commit().unwrap();
    assert!(db.read().unwrap().file(nested.ino).unwrap().is_some());

    let tx = db.write().unwrap();
    assert!(tx.delete_dir(child).unwrap());
    tx.commit().unwrap();
    let read = db.read().unwrap();
    assert!(read.dir(child).unwrap().is_none());
    assert!(read.dir_version_record(child).unwrap().is_none());
    assert!(read.file(nested.ino).unwrap().is_none());
}

#[test]
fn gc_chunks_removes_only_unreferenced_rows() {
    let (_dir, mut db) = temp_db(MmRole::Server, NAMESPACE);
    let data = b"chunk";
    let file = file_record(ino(1), ROOT_INO, "a", data);
    let chunks = chunk_refs(data);
    let tx = db.write().unwrap();
    tx.put_file(&file).unwrap();
    tx.put_chunk(chunks[0].hash, data).unwrap();
    tx.put_version(&VersionRecord {
        ino: file.ino,
        version: 1,
        size: file.size,
        file_root: file.file_root,
        content_hash: file.content_hash.unwrap(),
        chunk_count: 1,
        created_at_ms: 1,
    })
    .unwrap();
    tx.put_version_chunks(file.ino, 1, &chunks).unwrap();
    assert_eq!(tx.gc_chunks().unwrap(), 0);
    tx.put_version_chunks(file.ino, 1, &[]).unwrap();
    assert_eq!(tx.gc_chunks().unwrap(), 1);
    tx.commit().unwrap();
    assert!(db.read().unwrap().chunk(chunks[0].hash).unwrap().is_none());
}

#[test]
fn enum_text_and_tags_round_trip() {
    for kind in [EntryKind::File, EntryKind::Symlink, EntryKind::Dir] {
        assert_eq!(EntryKind::parse(kind.as_str()), Some(kind));
        assert_eq!(EntryKind::parse_tag(kind.tag()), Some(kind));
    }
    for op in [
        EntryOp::Keep,
        EntryOp::Put,
        EntryOp::Delete,
        EntryOp::Rename,
        EntryOp::DirAdd,
        EntryOp::DirRemove,
        EntryOp::DirRename,
    ] {
        assert_eq!(EntryOp::parse_tag(op.tag()), Some(op));
    }
    for phase in [
        Phase::Absent,
        Phase::Manifest,
        Phase::CheckingOut,
        Phase::Ready,
        Phase::Stale,
        Phase::Failed,
    ] {
        assert_eq!(Phase::parse(phase.as_str()), Some(phase));
    }
    for state in [
        UploadState::Open,
        UploadState::Uploading,
        UploadState::Verified,
        UploadState::Aborted,
    ] {
        assert_eq!(UploadState::parse(state.as_str()), Some(state));
    }
    assert_eq!(MmRole::parse(MmRole::Server.as_str()), Some(MmRole::Server));
    assert_eq!(MmRole::parse(MmRole::Client.as_str()), Some(MmRole::Client));
    assert!(BatchId::new_random().as_bytes() != &[0; 16]);
    assert!(LockId::new_random().as_bytes() != &[0; 16]);
    assert!(now_ms() > 0);
}

#[test]
fn name_and_path_validation_rejects_non_canonical_input() {
    for name in ["a", "a.b", "..hidden", "a b", &"x".repeat(255)] {
        assert!(validate_name(name).is_ok(), "{name}");
    }
    for name in ["", ".", "..", "a/b", "a\0b", &"x".repeat(256)] {
        assert!(validate_name(name).is_err(), "{name}");
    }

    for path in ["/", "/a", "/a/b", "/a..b", "/..."] {
        assert!(validate_dir_path(path).is_ok(), "{path}");
    }
    for path in [
        "",
        "a",
        "/a/",
        "/a//b",
        "/a/./b",
        "/a/../b",
        "/.",
        "/..",
        "/a\0b",
        &format!("/{}", "x".repeat(4096)),
    ] {
        assert!(validate_dir_path(path).is_err(), "{path}");
    }

    for namespace in ["/private-mm", "/public-mm", "/a"] {
        assert!(validate_namespace(namespace).is_ok(), "{namespace}");
    }
    for namespace in ["", "/", "private-mm", "/a/", "/a//b", "/a/../b"] {
        assert!(validate_namespace(namespace).is_err(), "{namespace}");
    }
}
