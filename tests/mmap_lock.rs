//! Library-level upload-lock and batch-idempotency tests.
//!
//! The HTTP policy (`423` on a foreign lock, one upload attempt per fsync,
//! next-fsync retry) lives in the not-yet-landed mm server/client. What can
//! be tested today is the storage contract those layers depend on:
//!
//! * one row per `(namespace, dir_path)`, one row per `lock_id`;
//! * TTL sweeps remove exactly the expired rows and leave live rows intact;
//! * renew/release are idempotent;
//! * a repeated `batch_id` or upload never creates a second row and never
//!   rewrites the first committed result.
//!
//! The server-level cases are in `e2e_mmap` and `mmap_recovery`, ignored until
//! `src/mmap/server.rs` lands.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod mmap_harness;

use mmap_harness::MmapEnv;

use syncmount::mmap::{
    BatchId, BatchRecord, DirSeq, Hash, LockId, LockRecord, MmRole, MmSeq, MmTx, UploadRecord,
    UploadState, now_ms,
};

const NAMESPACE: &str = "/private-mm";

#[test]
fn lock_storage_is_idempotent_and_renewable() {
    let env = MmapEnv::new();
    let mut db = env.mm_db(MmRole::Server, NAMESPACE, "server-mm.db");
    let id = LockId::from_bytes([0x01; 16]);
    let now = now_ms();

    {
        let tx = db.write().unwrap();
        tx.put_lock(&lock(id, "/", now + 60_000)).unwrap();
        tx.commit().unwrap();
    }
    let reader = db.read().unwrap();
    let first = reader.lock_for_dir("/").unwrap().unwrap();
    assert_eq!(first.lock_id, id);
    assert_eq!(first.base_seq, DirSeq::new(4));
    drop(reader);

    // Re-acquiring the same row is an upsert, not a second lease.
    {
        let tx = db.write().unwrap();
        tx.put_lock(&lock(id, "/", now + 90_000)).unwrap();
        tx.commit().unwrap();
    }
    let reader = db.read().unwrap();
    let second = reader.lock_for_dir("/").unwrap().unwrap();
    assert_eq!(second.lock_id, id);
    assert_eq!(second.expires_at_ms, now + 90_000);
    assert_eq!(second.progress_bytes, 0);
    drop(reader);

    {
        let tx = db.write().unwrap();
        assert!(tx.renew_lock(id, now + 120_000, 8 * 1024).unwrap());
        tx.commit().unwrap();
    }
    let reader = db.read().unwrap();
    let renewed = reader.lock(id).unwrap().unwrap();
    assert_eq!(renewed.expires_at_ms, now + 120_000);
    assert_eq!(renewed.progress_bytes, 8 * 1024);
    drop(reader);

    {
        let tx = db.write().unwrap();
        assert!(tx.delete_lock(id).unwrap());
        assert!(!tx.delete_lock(id).unwrap());
        tx.commit().unwrap();
    }
    assert!(db.read().unwrap().lock(id).unwrap().is_none());
}

#[test]
fn ttl_sweep_removes_only_expired_locks() {
    let env = MmapEnv::new();
    let mut db = env.mm_db(MmRole::Server, NAMESPACE, "server-mm.db");
    let now = now_ms();
    let live = LockId::from_bytes([0x0a; 16]);
    let expired = LockId::from_bytes([0x0b; 16]);
    let second = LockId::from_bytes([0x0c; 16]);

    {
        let tx = db.write().unwrap();
        tx.put_lock(&lock(live, "/", now + 60_000)).unwrap();
        tx.put_lock(&lock(expired, "/a", now - 1)).unwrap();
        tx.put_lock(&lock(second, "/b", now + 1)).unwrap();
        tx.commit().unwrap();
    }

    {
        let tx = db.write().unwrap();
        assert_eq!(
            tx.delete_expired_locks(now).unwrap(),
            vec![expired],
            "strict `expires_at_ms < now` must leave the row expiring now"
        );
        tx.commit().unwrap();
    }
    let reader = db.read().unwrap();
    assert!(reader.lock(live).unwrap().is_some());
    assert!(reader.lock(expired).unwrap().is_none());
    assert!(reader.lock(second).unwrap().is_some());
    drop(reader);

    {
        let tx = db.write().unwrap();
        assert_eq!(tx.delete_expired_locks(now + 2).unwrap(), vec![second]);
        assert_eq!(tx.delete_expired_locks(now + 2).unwrap(), Vec::new());
        assert_eq!(tx.delete_expired_locks(now + 120_000).unwrap(), vec![live]);
        tx.commit().unwrap();
    }
    assert!(db.read().unwrap().lock_for_dir("/").unwrap().is_none());
}

#[test]
fn one_lock_row_per_directory_and_replacement_drops_the_old_id() {
    let env = MmapEnv::new();
    let mut db = env.mm_db(MmRole::Server, NAMESPACE, "server-mm.db");
    let now = now_ms();
    let first = LockId::from_bytes([0x11; 16]);
    let replacement = LockId::from_bytes([0x12; 16]);
    let other = LockId::from_bytes([0x13; 16]);

    {
        let tx = db.write().unwrap();
        tx.put_lock(&lock(first, "/", now + 60_000)).unwrap();
        tx.put_lock(&lock(other, "/a", now + 60_000)).unwrap();
        tx.commit().unwrap();
    }
    {
        let tx = db.write().unwrap();
        tx.put_lock(&lock(replacement, "/", now + 60_000)).unwrap();
        tx.commit().unwrap();
    }

    let reader = db.read().unwrap();
    assert_eq!(
        reader.lock_for_dir("/").unwrap().unwrap().lock_id,
        replacement
    );
    assert!(reader.lock(first).unwrap().is_none());
    assert_eq!(reader.lock_for_dir("/a").unwrap().unwrap().lock_id, other);
}

#[test]
fn upload_and_batch_idempotency_keep_the_first_committed_result() {
    let env = MmapEnv::new();
    let mut db = env.mm_db(MmRole::Server, NAMESPACE, "server-mm.db");
    let batch_id = BatchId::from_bytes([0x21; 16]);
    let lock_id = LockId::from_bytes([0x22; 16]);
    let manifest_hash: Hash = [0x23; 32];
    let now = now_ms();

    let mut upload = UploadRecord {
        batch_id,
        lock_id,
        dir_path: "/".to_owned(),
        dir_ino: [0; 16],
        base_epoch: 1,
        base_seq: DirSeq::new(1),
        dir_version: [0x24; 32],
        manifest_hash,
        state: UploadState::Open,
        spool_path: "/tmp/spool-test".to_owned(),
        bytes_received: 0,
        created_at_ms: now,
        updated_at_ms: now,
        expires_at_ms: now + 300_000,
    };
    {
        let tx = db.write().unwrap();
        tx.put_upload(&upload).unwrap();
        upload.bytes_received = 4096;
        upload.expires_at_ms = now + 600_000;
        tx.put_upload(&upload).unwrap();
        tx.commit().unwrap();
    }
    let reader = db.read().unwrap();
    let stored = reader.upload(batch_id).unwrap().unwrap();
    assert_eq!(stored.bytes_received, 4096);
    assert_eq!(stored.expires_at_ms, now + 600_000);
    assert_eq!(reader.uploads_for_lock(lock_id).unwrap().len(), 1);
    drop(reader);

    {
        let tx = db.write().unwrap();
        tx.set_upload_state(batch_id, UploadState::Verified)
            .unwrap();
        tx.update_upload_progress(batch_id, 8192, now + 700_000)
            .unwrap();
        tx.commit().unwrap();
    }
    let reader = db.read().unwrap();
    let stored = reader.upload(batch_id).unwrap().unwrap();
    assert_eq!(stored.state, UploadState::Verified);
    assert_eq!(stored.bytes_received, 8192);
    drop(reader);

    let first = BatchRecord {
        batch_id,
        dir_path: "/".to_owned(),
        dir_ino: [0; 16],
        base_epoch: 1,
        base_seq: DirSeq::new(1),
        base_seq_after: DirSeq::new(2),
        snapshot_seq: MmSeq::new(9),
        dir_version_before: [0x25; 32],
        dir_version_after: [0x26; 32],
        manifest_hash,
        client_id: [0x27; 16],
        entry_count: 1,
        bytes: 128,
        committed_at_ms: now,
    };
    {
        let tx = db.write().unwrap();
        assert!(tx.put_batch(&first).unwrap());
        assert!(!tx.put_batch(&first).unwrap());
        tx.commit().unwrap();
    }
    // A repeated id with a different result must not overwrite the original.
    let mut second = first.clone();
    second.snapshot_seq = MmSeq::new(10);
    second.base_seq_after = DirSeq::new(3);
    {
        let tx = db.write().unwrap();
        assert!(!tx.put_batch(&second).unwrap());
        tx.commit().unwrap();
    }
    let reader = db.read().unwrap();
    let stored = reader.batch(batch_id).unwrap().unwrap();
    assert_eq!(stored.snapshot_seq, MmSeq::new(9));
    assert_eq!(stored.base_seq_after, DirSeq::new(2));
    assert_eq!(reader.batch_by_snapshot(MmSeq::new(10)).unwrap(), None);
    drop(reader);

    {
        let tx = db.write().unwrap();
        assert!(tx.delete_upload(batch_id).unwrap());
        assert!(!tx.delete_upload(batch_id).unwrap());
        tx.commit().unwrap();
    }
    assert!(db.read().unwrap().upload(batch_id).unwrap().is_none());
}

fn lock(id: LockId, path: &str, expires_at_ms: i64) -> LockRecord {
    let now = now_ms();
    LockRecord {
        lock_id: id,
        dir_path: path.to_owned(),
        dir_ino: [0x30; 16],
        owner_client: [0x31; 16],
        owner_session: [0x32; 16],
        base_epoch: 1,
        base_seq: DirSeq::new(4),
        batch_id: Some(BatchId::from_bytes([0x33; 16])),
        expires_at_ms,
        created_at_ms: now,
        renewed_at_ms: now,
        progress_bytes: 0,
    }
}
