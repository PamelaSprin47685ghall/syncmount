//! Library-level integration tests for the 1.1 `--mmap` pieces that exist
//! today: the mm database, canonical manifests, the SMM1 codec and the rsync
//! engine.
//!
//! These tests do not start a server or mount FUSE. They are the executable
//! half of the verification matrix that only needs the real library modules:
//!
//! * manifest -> rsync -> apply -> whole-file verify -> database round-trip;
//! * the `if_dir_version` precondition for a 304 checkout response;
//! * independent `mm_seq` / `dir_seq` / base-triple bookkeeping.
//!
//! Server- and mount-dependent cases live in `e2e_mmap`, `chaos_mmap` and
//! `mmap_recovery`, which are ignored until `src/mmap/{server,client,shadow}`
//! lands.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod mmap_harness;

use mmap_harness::MmapEnv;

use syncmount::mmap::base::dir_version;
use syncmount::mmap::manifest::Manifest;
use syncmount::mmap::proto::{
    Checkout, DirAttrs as WireDirAttrs, Entry as WireEntry, EntryKind as WireEntryKind,
    EntryOp as WireEntryOp, Limits, Snapshot, decode_frame, encode_frame,
};
use syncmount::mmap::rsync::{apply_exact, block_size_for, delta, file_hash, sign, verify};
use syncmount::mmap::{
    BatchId, BatchRecord, DirAttrs, DirRecord, DirSeq, EntryKind, FileRecord, Hash, Ino, MmBase,
    MmRole, MmSeq, MmTx, Phase, ROOT_INO, WriteTx, now_ms,
};
use syncmount::store::sqlite::{ChunkRef, chunk_hash};

const NAMESPACE: &str = "/private-mm";

#[test]
fn manifest_rsync_apply_verify_round_trip() {
    let env = MmapEnv::new();
    let mut db = env.mm_db(MmRole::Server, NAMESPACE, "server-mm.db");
    let root = db.read().unwrap().dir(ROOT_INO).unwrap().unwrap();
    let ino: Ino = [0x11; 16];
    let old = pattern(200 * 1024 + 17, 0x5a);

    let tx = db.write().unwrap();
    let old_record = store_file(&tx, ROOT_INO, ino, "app.db", &old, root.attrs, 1);
    let before = Manifest::from_records(std::slice::from_ref(&old_record)).unwrap();
    let before_version = dir_version(NAMESPACE, ROOT_INO, &root.attrs, before.entries());
    let seq_before = tx.next_mm_seq().unwrap();
    tx.set_dir_snapshot(ROOT_INO, seq_before).unwrap();
    tx.set_base(ROOT_INO, &MmBase::new(1, DirSeq::new(1), before_version))
        .unwrap();
    tx.replace_base_manifest(ROOT_INO, &before).unwrap();
    tx.commit().unwrap();

    let snapshot = db.read().unwrap();
    assert_eq!(
        Manifest::from_base_entries(snapshot.base_manifest(ROOT_INO).unwrap())
            .unwrap()
            .entries(),
        before.entries()
    );
    assert_eq!(read_content(&snapshot, ino, 1).unwrap(), old);
    drop(snapshot);

    // The server can rebuild the base bytes, then apply a delta against them.
    let new = mutate(&old);
    let block = block_size_for(old.len() as u64);
    let signature = sign(&old[..], block).unwrap();
    let instructions = delta(&new, &signature).unwrap();
    let rebuilt = apply_exact(&old, &instructions, new.len() as u64).unwrap();
    assert_eq!(rebuilt, new, "delta round-trip changed bytes");
    assert!(verify(&new, new.len() as u64, &file_hash(&new)));

    let reader = db.read().unwrap();
    let stored_base = reader.base_manifest(ROOT_INO).unwrap();
    assert!(stored_base.iter().any(|entry| entry.name == "app.db"));
    let reconstructed = old.clone();
    let from_db = apply_exact(&reconstructed, &instructions, new.len() as u64).unwrap();
    assert_eq!(from_db, new, "delta applied to base rows changed bytes");
    drop(reader);

    let tx = db.write().unwrap();
    let new_record = store_file(&tx, ROOT_INO, ino, "app.db", &new, root.attrs, 2);
    let after = Manifest::from_records(std::slice::from_ref(&new_record)).unwrap();
    let delta_manifest = Manifest::diff(before.entries(), after.entries()).unwrap();
    assert_eq!(delta_manifest.len(), 1);
    assert_eq!(
        delta_manifest.get("app.db").unwrap().op,
        syncmount::mmap::EntryOp::Put
    );
    let after_version = dir_version(NAMESPACE, ROOT_INO, &root.attrs, after.entries());
    let seq_after = tx.next_mm_seq().unwrap();
    let dir_seq = tx.bump_dir(ROOT_INO).unwrap();
    tx.set_dir_snapshot(ROOT_INO, seq_after).unwrap();
    tx.set_base(ROOT_INO, &MmBase::new(1, dir_seq, after_version))
        .unwrap();
    tx.replace_base_manifest(ROOT_INO, &delta_manifest).unwrap();
    tx.commit().unwrap();

    let reader = db.read().unwrap();
    assert_eq!(read_content(&reader, ino, 2).unwrap(), new);
    assert_eq!(reader.dir_version(ROOT_INO).unwrap(), Some(after_version));
    assert_eq!(
        reader.base(ROOT_INO).unwrap(),
        Some(MmBase::new(1, dir_seq, after_version))
    );
    assert!(seq_after > seq_before);
    let stored = reader.file(ino).unwrap().unwrap();
    assert_eq!(stored.size, new.len() as u64);
    assert_eq!(stored.file_root, file_root_of(&new));
    assert!(verify(
        &read_content(&reader, ino, 2).unwrap(),
        stored.size,
        &stored.content_hash.unwrap()
    ));
}

#[test]
fn unrelated_directory_commit_preserves_dir_version_for_304() {
    let env = MmapEnv::new();
    let mut db = env.mm_db(MmRole::Server, NAMESPACE, "server-mm.db");
    let root = db.read().unwrap().dir(ROOT_INO).unwrap().unwrap();
    let child: Ino = [0x22; 16];
    let ino: Ino = [0x23; 16];
    let data = pattern(32 * 1024 + 3, 0x31);

    // Root owns one file; /a is an empty child directory.
    let tx = db.write().unwrap();
    put_child_dir(&tx, ROOT_INO, child, "a", root.attrs);
    let file = store_file(&tx, ROOT_INO, ino, "app.db", &data, root.attrs, 1);
    let root_entries = Manifest::new(vec![
        dir_entry(child, "a", root.attrs),
        file.manifest_entry(syncmount::mmap::EntryOp::Keep),
    ])
    .unwrap();
    let root_version = dir_version(NAMESPACE, ROOT_INO, &root.attrs, root_entries.entries());
    let seq1 = tx.next_mm_seq().unwrap();
    let root_seq1 = tx.bump_dir(ROOT_INO).unwrap();
    tx.set_dir_snapshot(ROOT_INO, seq1).unwrap();
    tx.set_base(ROOT_INO, &MmBase::new(1, root_seq1, root_version))
        .unwrap();
    tx.replace_base_manifest(ROOT_INO, &root_entries).unwrap();
    let a_attrs = root.attrs;
    let empty = Manifest::default();
    let a_version = dir_version(NAMESPACE, child, &a_attrs, empty.entries());
    let a_seq1 = tx.bump_dir(child).unwrap();
    tx.set_dir_snapshot(child, seq1).unwrap();
    tx.set_base(child, &MmBase::new(1, a_seq1, a_version))
        .unwrap();
    tx.commit().unwrap();

    // A commit in /a advances the global sequence only.
    let tx = db.write().unwrap();
    let mut child_record = tx.dir(child).unwrap().unwrap();
    child_record.attrs.mtime_ns += 1;
    tx.put_dir(&child_record).unwrap();
    let a_version2 = dir_version(NAMESPACE, child, &child_record.attrs, empty.entries());
    let seq2 = tx.next_mm_seq().unwrap();
    let a_seq2 = tx.bump_dir(child).unwrap();
    tx.set_dir_snapshot(child, seq2).unwrap();
    tx.set_base(child, &MmBase::new(1, a_seq2, a_version2))
        .unwrap();
    tx.commit().unwrap();

    let reader = db.read().unwrap();
    assert_eq!(reader.mm_seq().unwrap(), seq2);
    assert!(seq2 > seq1);
    assert_eq!(reader.dir_seq(ROOT_INO).unwrap(), Some(root_seq1));
    assert_eq!(reader.dir_version(ROOT_INO).unwrap(), Some(root_version));
    assert_eq!(reader.dir_seq(child).unwrap(), Some(a_seq2));
    assert_ne!(reader.dir_version(child).unwrap(), Some(a_version));
    drop(reader);

    // The SMM1 request keeps the version that makes a 304 possible.
    let request = Checkout {
        // The wire namespace is the URL path label without a leading slash;
        // the mm database stores the canonical absolute form.
        namespace: "private-mm".to_owned(),
        dir_path: "/".to_owned(),
        bodies: 0,
        if_dir_version: Some(root_version),
        if_snapshot_seq: Some(seq1.get()),
    };
    let limits = Limits::new();
    let (header, meta) = encode_frame(&request, &limits).unwrap();
    let decoded: Checkout = decode_frame(&header, &meta).unwrap();
    assert_eq!(decoded, request);

    // A snapshot built from the same database rows encodes and decodes.
    let reader = db.read().unwrap();
    let root_record = reader.dir(ROOT_INO).unwrap().unwrap();
    let entries = reader.files(ROOT_INO).unwrap();
    let wire_entries = entries.iter().map(wire_entry).collect::<Vec<_>>();
    let snapshot = Snapshot {
        snapshot_seq: seq1.get(),
        epoch: root_record.base.epoch,
        base_seq: root_seq1.get(),
        dir_ino: ROOT_INO,
        dir_path: "/".to_owned(),
        dir_version: root_version,
        dir_attrs: wire_attrs(root.attrs),
        entries: wire_entries,
    };
    let (header, meta) = encode_frame(&snapshot, &limits).unwrap();
    let decoded: Snapshot = decode_frame(&header, &meta).unwrap();
    assert_eq!(decoded, snapshot);
    assert_eq!(decoded.dir_version, root_version);

    // Committing root changes its version, so the same `if_dir_version`
    // must not produce a 304.
    let tx = db.write().unwrap();
    let changed = pattern(32 * 1024 + 4, 0x32);
    let file = store_file(&tx, ROOT_INO, ino, "app.db", &changed, root.attrs, 2);
    let changed_manifest = Manifest::new(vec![
        dir_entry(child, "a", root.attrs),
        file.manifest_entry(syncmount::mmap::EntryOp::Put),
    ])
    .unwrap();
    let changed_version = dir_version(NAMESPACE, ROOT_INO, &root.attrs, changed_manifest.entries());
    let seq3 = tx.next_mm_seq().unwrap();
    tx.bump_dir(ROOT_INO).unwrap();
    tx.set_dir_snapshot(ROOT_INO, seq3).unwrap();
    tx.set_base(
        ROOT_INO,
        &MmBase::new(1, tx.dir_seq(ROOT_INO).unwrap().unwrap(), changed_version),
    )
    .unwrap();
    tx.replace_base_manifest(ROOT_INO, &changed_manifest)
        .unwrap();
    tx.commit().unwrap();

    let reader = db.read().unwrap();
    assert_ne!(reader.dir_version(ROOT_INO).unwrap(), Some(root_version));
}

#[test]
fn mm_seq_dir_seq_and_base_stay_in_their_own_spaces() {
    let env = MmapEnv::new();
    let mut db = env.mm_db(MmRole::Server, NAMESPACE, "server-mm.db");
    let root = db.read().unwrap().dir(ROOT_INO).unwrap().unwrap();
    let child: Ino = [0x33; 16];

    let tx = db.write().unwrap();
    put_child_dir(&tx, ROOT_INO, child, "a", root.attrs);
    let root_manifest = Manifest::new(vec![dir_entry(child, "a", root.attrs)]).unwrap();
    let root_version = dir_version(NAMESPACE, ROOT_INO, &root.attrs, root_manifest.entries());
    let seq1 = tx.next_mm_seq().unwrap();
    let root_seq1 = tx.bump_dir(ROOT_INO).unwrap();
    tx.set_dir_snapshot(ROOT_INO, seq1).unwrap();
    let root_base = MmBase::new(1, root_seq1, root_version);
    tx.set_base(ROOT_INO, &root_base).unwrap();
    tx.replace_base_manifest(ROOT_INO, &root_manifest).unwrap();
    let batch1 = BatchId::from_bytes([0x41; 16]);
    assert!(
        tx.put_batch(&batch(
            batch1,
            "/",
            ROOT_INO,
            root_base,
            root_seq1,
            seq1,
            root_manifest.hash(),
        ))
        .unwrap()
    );
    tx.commit().unwrap();

    let tx = db.write().unwrap();
    let empty = Manifest::default();
    let a_version = dir_version(NAMESPACE, child, &root.attrs, empty.entries());
    let seq2 = tx.next_mm_seq().unwrap();
    let a_seq2 = tx.bump_dir(child).unwrap();
    tx.set_dir_snapshot(child, seq2).unwrap();
    let a_base = MmBase::new(1, a_seq2, a_version);
    tx.set_base(child, &a_base).unwrap();
    let batch2 = BatchId::from_bytes([0x42; 16]);
    assert!(
        tx.put_batch(&batch(
            batch2,
            "/a",
            child,
            a_base,
            a_seq2,
            seq2,
            empty.hash(),
        ))
        .unwrap()
    );
    tx.commit().unwrap();

    assert_eq!(seq2.get(), seq1.get() + 1);
    // Both directories start at 1 and receive one bump; the sequences are
    // independent, not additive.
    assert_eq!(root_seq1.get(), 2);
    assert_eq!(a_seq2.get(), 2);
    let reader = db.read().unwrap();
    assert_eq!(reader.mm_seq().unwrap(), seq2);
    assert_eq!(reader.dir_seq(ROOT_INO).unwrap(), Some(root_seq1));
    assert_eq!(reader.dir_seq(child).unwrap(), Some(a_seq2));
    assert_eq!(reader.base(ROOT_INO).unwrap(), Some(root_base));
    assert_eq!(reader.base(child).unwrap(), Some(a_base));
    assert_eq!(reader.dir(ROOT_INO).unwrap().unwrap().base, root_base);
    assert_eq!(reader.dir(child).unwrap().unwrap().base, a_base);
    let stored1 = reader.batch(batch1).unwrap().unwrap();
    let stored2 = reader.batch(batch2).unwrap().unwrap();
    assert_eq!(stored1.snapshot_seq, seq1);
    assert_eq!(stored2.snapshot_seq, seq2);
    assert_eq!(
        reader.batch_by_snapshot(seq1).unwrap().unwrap().batch_id,
        batch1
    );
    assert_eq!(
        reader.batch_by_snapshot(seq2).unwrap().unwrap().batch_id,
        batch2
    );
    assert_eq!(stored1.base_seq_after, root_seq1);
    assert_eq!(stored2.base_seq_after, a_seq2);
}

#[test]
fn contract_denies_an_immediate_second_reader_visibility() {
    // A read snapshot opened before a commit must keep the old sequence and
    // directory version; a new reader must see the new ones. This is the
    // isolation property every checkout relies on.
    let env = MmapEnv::new();
    let mut db = env.mm_db(MmRole::Server, NAMESPACE, "server-mm.db");
    let root = db.read().unwrap().dir(ROOT_INO).unwrap().unwrap();
    let ino: Ino = [0x44; 16];
    let old = pattern(8 * 1024, 0x44);

    let tx = db.write().unwrap();
    let record = store_file(&tx, ROOT_INO, ino, "a.bin", &old, root.attrs, 1);
    let manifest = Manifest::from_records(&[record]).unwrap();
    let version = dir_version(NAMESPACE, ROOT_INO, &root.attrs, manifest.entries());
    let seq1 = tx.next_mm_seq().unwrap();
    tx.set_dir_snapshot(ROOT_INO, seq1).unwrap();
    tx.set_base(ROOT_INO, &MmBase::new(1, DirSeq::new(1), version))
        .unwrap();
    tx.commit().unwrap();

    let before = db.read().unwrap();
    let before_seq = before.mm_seq().unwrap();
    let before_version = before.dir_version(ROOT_INO).unwrap();

    let tx = db.write().unwrap();
    let mut root_record = tx.dir(ROOT_INO).unwrap().unwrap();
    root_record.attrs.mtime_ns += 1;
    tx.put_dir(&root_record).unwrap();
    let changed_version = dir_version(NAMESPACE, ROOT_INO, &root_record.attrs, manifest.entries());
    let next_seq = tx.next_mm_seq().unwrap();
    let next_dir_seq = tx.bump_dir(ROOT_INO).unwrap();
    tx.set_dir_snapshot(ROOT_INO, next_seq).unwrap();
    tx.set_base(ROOT_INO, &MmBase::new(1, next_dir_seq, changed_version))
        .unwrap();
    tx.commit().unwrap();

    assert_eq!(before.mm_seq().unwrap(), before_seq);
    assert_eq!(before.dir_version(ROOT_INO).unwrap(), before_version);
    let after = db.read().unwrap();
    assert!(after.mm_seq().unwrap() > before_seq);
    assert_ne!(after.dir_version(ROOT_INO).unwrap(), before_version);
}

/// A deterministic byte pattern with no test-only RNG dependency.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    let mut state = u64::from(seed).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut out = Vec::with_capacity(len);
    for index in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push((state >> 24) as u8 ^ (index as u8).wrapping_mul(0x1d));
    }
    out
}

/// Replace, insert and delete bytes so the delta must mix COPY and LITERAL.
fn mutate(old: &[u8]) -> Vec<u8> {
    let mut out = old.to_vec();
    if out.len() > 160 * 1024 {
        for (offset, byte) in out[100_000..100_128].iter_mut().enumerate() {
            *byte = (offset as u8).wrapping_mul(7);
        }
    }
    let insert_at = out.len().min(50_000);
    out.splice(
        insert_at..insert_at,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11],
    );
    let delete_at = out.len().min(150_000);
    out.drain(delete_at..(delete_at + 3).min(out.len()));
    out
}

fn chunk_refs(data: &[u8]) -> Vec<ChunkRef> {
    data.chunks(syncmount::mmap::CHUNK_BYTES as usize)
        .enumerate()
        .map(|(index, bytes)| ChunkRef {
            chunk_no: index as u32,
            hash: chunk_hash(bytes),
            offset: index as u64 * u64::from(syncmount::mmap::CHUNK_BYTES),
            len: bytes.len() as u32,
        })
        .collect()
}

fn file_root_of(data: &[u8]) -> Hash {
    let chunks = chunk_refs(data);
    syncmount::mmap::file_root(EntryKind::File, None, &chunks)
}

fn store_file(
    tx: &WriteTx<'_>,
    dir_ino: Ino,
    ino: Ino,
    name: &str,
    data: &[u8],
    attrs: DirAttrs,
    version: u64,
) -> FileRecord {
    let chunks = chunk_refs(data);
    for chunk in data.chunks(syncmount::mmap::CHUNK_BYTES as usize) {
        tx.put_chunk(chunk_hash(chunk), chunk).unwrap();
    }
    let file_root = syncmount::mmap::file_root(EntryKind::File, None, &chunks);
    let content_hash = *blake3::hash(data).as_bytes();
    let now = now_ms();
    let record = FileRecord {
        ino,
        dir_ino,
        name: name.to_owned(),
        kind: EntryKind::File,
        attrs,
        size: data.len() as u64,
        file_root,
        content_hash: Some(content_hash),
        target: None,
        version,
        deleted: false,
        created_at_ms: now,
        updated_at_ms: now,
    };
    // `mm_versions` and `mm_version_chunks` reference `mm_files`, so the
    // entry row must exist before its content rows.
    tx.put_file(&record).unwrap();
    tx.put_version(&syncmount::mmap::VersionRecord {
        ino,
        version,
        size: data.len() as u64,
        file_root,
        content_hash,
        chunk_count: chunks.len() as u32,
        created_at_ms: now,
    })
    .unwrap();
    tx.put_version_chunks(ino, version, &chunks).unwrap();
    record
}

fn read_content(
    tx: &impl MmTx,
    ino: Ino,
    version: u64,
) -> Result<Vec<u8>, syncmount::mmap::MmError> {
    let chunks = tx.version_chunks(ino, version)?;
    let mut out = Vec::new();
    for chunk in chunks {
        let bytes = tx
            .chunk(chunk.hash)?
            .ok_or(syncmount::mmap::MmError::NotFound)?;
        assert_eq!(bytes.len(), chunk.len as usize);
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

fn put_child_dir(tx: &WriteTx<'_>, parent: Ino, ino: Ino, name: &str, attrs: DirAttrs) {
    let now = now_ms();
    tx.put_dir(&DirRecord {
        ino,
        path: format!("/{name}"),
        base: MmBase::new(1, DirSeq::new(1), syncmount::mmap::dir_root()),
        phase: Phase::Ready,
        attrs,
        deleted: false,
        created_at_ms: now,
        updated_at_ms: now,
    })
    .unwrap();
    tx.put_file(&FileRecord {
        ino,
        dir_ino: parent,
        name: name.to_owned(),
        kind: EntryKind::Dir,
        attrs,
        size: 0,
        file_root: syncmount::mmap::dir_root(),
        content_hash: None,
        target: None,
        version: 0,
        deleted: false,
        created_at_ms: now,
        updated_at_ms: now,
    })
    .unwrap();
}

fn dir_entry(ino: Ino, name: &str, attrs: DirAttrs) -> syncmount::mmap::ManifestEntry {
    syncmount::mmap::ManifestEntry {
        name: name.to_owned(),
        ino,
        kind: EntryKind::Dir,
        op: syncmount::mmap::EntryOp::Keep,
        from_name: None,
        mode: attrs.mode,
        uid: attrs.uid,
        gid: attrs.gid,
        mtime_ns: attrs.mtime_ns,
        size: 0,
        file_root: syncmount::mmap::dir_root(),
        content_hash: None,
        target: None,
    }
}

fn wire_entry(record: &FileRecord) -> WireEntry {
    WireEntry {
        name: record.name.clone(),
        ino: Some(record.ino),
        kind: match record.kind {
            EntryKind::File => WireEntryKind::File,
            EntryKind::Symlink => WireEntryKind::Symlink,
            EntryKind::Dir => WireEntryKind::Dir,
        },
        op: WireEntryOp::Keep,
        from_name: None,
        mode: record.attrs.mode,
        uid: record.attrs.uid,
        gid: record.attrs.gid,
        mtime_ns: record.attrs.mtime_ns as u64,
        size: record.size,
        file_root: Some(record.file_root),
        content_hash: record.content_hash,
        target: record.target.clone(),
    }
}

fn wire_attrs(attrs: DirAttrs) -> WireDirAttrs {
    WireDirAttrs {
        mode: attrs.mode,
        uid: attrs.uid,
        gid: attrs.gid,
        mtime_ns: attrs.mtime_ns as u64,
    }
}

#[allow(clippy::too_many_arguments)]
fn batch(
    batch_id: BatchId,
    dir_path: &str,
    dir_ino: Ino,
    base: MmBase,
    after: DirSeq,
    snapshot: MmSeq,
    manifest_hash: Hash,
) -> BatchRecord {
    BatchRecord {
        batch_id,
        dir_path: dir_path.to_owned(),
        dir_ino,
        base_epoch: base.epoch,
        base_seq: base.dir_seq,
        base_seq_after: after,
        snapshot_seq: snapshot,
        dir_version_before: base.dir_version,
        dir_version_after: base.dir_version,
        manifest_hash,
        client_id: [0x51; 16],
        entry_count: 1,
        bytes: 0,
        committed_at_ms: now_ms(),
    }
}
