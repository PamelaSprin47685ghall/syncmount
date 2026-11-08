//! Directory upload locks: acquire, renew, release and expiry collection.
//!
//! The lock key is `(namespace, canonical dir_path)`; the owner is the
//! authenticated client id. Checkout never reads this table, so a reader is
//! never blocked by an upload. A lock is only a mutual-exclusion lease for
//! writers of one directory, not a read barrier.

use crate::mmap::db::{MmTx, WriteTx};
use crate::mmap::now_ms;
use crate::mmap::proto::{
    ErrorCode, LockAcquire, LockGranted, LockRelease, LockRenew, LockRenewed,
};
use crate::mmap::types::{BatchId, DirSeq, LockId, LockRecord, UploadState};

use super::http::{self, Response};
use super::{Fault, ServerState, SessionInfo};

impl ServerState {
    /// `LOCK_ACQUIRE`.
    pub async fn lock_acquire(
        &self,
        request: LockAcquire,
        session: SessionInfo,
    ) -> Result<Response, Fault> {
        self.check_wire_namespace(&request.namespace)?;
        if request.client_id != session.client_id || request.session_id != session.session_id {
            return Err(Fault::detail(
                ErrorCode::AuthFailed,
                "lock request does not match the authenticated session",
            ));
        }
        let mut db = self.writer().lock().await;
        let tx = db.write()?;
        let Some(dir) = tx.dir_by_path(&request.dir_path)? else {
            return Err(Fault::detail(
                ErrorCode::DirNotFound,
                format!("directory {} does not exist", request.dir_path),
            ));
        };
        let now = now_ms();
        let ttl = i64::try_from(self.config().lock_ttl_ms).unwrap_or(i64::MAX);
        let expires = now.saturating_add(ttl);
        let mut stale_spools = Vec::new();

        if let Some(lock) = tx.lock_for_dir(&request.dir_path)? {
            if lock.expires_at_ms < now {
                stale_spools.extend(abort_uploads(&tx, lock.lock_id)?);
                tx.delete_lock(lock.lock_id)?;
            } else if lock.owner_client == session.client_id {
                if request.lock_id != Some(*lock.lock_id.as_bytes()) {
                    return Err(Fault::lock_lost(
                        "this client already holds a different lock id",
                    ));
                }
                let refreshed = LockRecord {
                    owner_session: session.session_id,
                    expires_at_ms: expires,
                    renewed_at_ms: now,
                    batch_id: lock.batch_id,
                    ..lock
                };
                tx.put_lock(&refreshed)?;
                let snapshot_seq = tx.mm_seq()?;
                tx.commit()?;
                drop(db);
                remove_spools(self, stale_spools);
                return http::message_response(&granted(
                    &refreshed,
                    &dir.path,
                    dir.base.dir_version,
                    snapshot_seq.get(),
                    self.config().lock_ttl_ms,
                ));
            } else {
                return Err(Fault::lock_held(&lock));
            }
        }

        let lock = LockRecord {
            lock_id: LockId::new_random(),
            dir_path: dir.path.clone(),
            dir_ino: dir.ino,
            owner_client: session.client_id,
            owner_session: session.session_id,
            base_epoch: dir.base.epoch,
            base_seq: dir.base.dir_seq,
            batch_id: None,
            expires_at_ms: expires,
            created_at_ms: now,
            renewed_at_ms: now,
            progress_bytes: 0,
        };
        tx.put_lock(&lock)?;
        let snapshot_seq = tx.mm_seq()?;
        tx.commit()?;
        drop(db);
        remove_spools(self, stale_spools);
        http::message_response(&granted(
            &lock,
            &request.dir_path,
            dir.base.dir_version,
            snapshot_seq.get(),
            self.config().lock_ttl_ms,
        ))
    }

    /// `LOCK_RENEW`.
    pub async fn lock_renew(
        &self,
        request: LockRenew,
        session: SessionInfo,
    ) -> Result<Response, Fault> {
        let lock_id = LockId::from_bytes(request.lock_id);
        let mut db = self.writer().lock().await;
        let tx = db.write()?;
        let Some(lock) = tx.lock(lock_id)? else {
            return Err(Fault::lock_lost("lock does not exist"));
        };
        if lock.owner_client != session.client_id {
            return Err(Fault::lock_lost("lock belongs to another client"));
        }
        let now = now_ms();
        if lock.expires_at_ms < now {
            let spools = abort_uploads(&tx, lock.lock_id)?;
            tx.delete_lock(lock.lock_id)?;
            tx.commit()?;
            drop(db);
            remove_spools(self, spools);
            return Err(Fault::lock_expired(&lock));
        }
        let ttl = i64::try_from(self.config().lock_ttl_ms).unwrap_or(i64::MAX);
        let expires = now.saturating_add(ttl);
        let progress = request.progress_bytes.unwrap_or(lock.progress_bytes);
        if !tx.renew_lock(lock_id, expires, progress)? {
            return Err(Fault::lock_lost("lock disappeared during renewal"));
        }
        tx.commit()?;
        drop(db);
        http::message_response(&LockRenewed {
            lock_id: request.lock_id,
            expires_at_ms: u64::try_from(expires).unwrap_or(u64::MAX),
        })
    }

    /// `LOCK_RELEASE`. Releasing an unknown lock is a successful no-op.
    pub async fn lock_release(
        &self,
        request: LockRelease,
        session: SessionInfo,
    ) -> Result<Response, Fault> {
        let lock_id = LockId::from_bytes(request.lock_id);
        let mut db = self.writer().lock().await;
        let tx = db.write()?;
        let Some(lock) = tx.lock(lock_id)? else {
            return Ok(http::empty_response(204));
        };
        if lock.owner_client != session.client_id {
            return Err(Fault::lock_lost("lock belongs to another client"));
        }
        let spools = abort_uploads(&tx, lock.lock_id)?;
        tx.delete_lock(lock.lock_id)?;
        tx.commit()?;
        drop(db);
        remove_spools(self, spools);
        Ok(http::empty_response(204))
    }

    /// Collect expired locks and uploads. Runs every [`super::SWEEP_INTERVAL`]
    /// and is safe to call directly from tests.
    pub async fn sweep_once(&self) {
        let mut db = self.writer().lock().await;
        let Ok(tx) = db.write() else {
            return;
        };
        let now = now_ms();
        let mut spools = Vec::new();
        match tx.delete_expired_locks(now) {
            Ok(ids) => {
                for lock_id in ids {
                    if let Ok(paths) = abort_uploads(&tx, lock_id) {
                        spools.extend(paths);
                    }
                }
            }
            Err(_) => return,
        }
        let expired_uploads: Vec<(BatchId, String)> = {
            let Ok(mut stmt) = tx.conn().prepare(
                "SELECT batch_id, spool_path FROM mm_uploads
                 WHERE state <> 'aborted' AND expires_at_ms < ?1",
            ) else {
                return;
            };
            let Ok(rows) = stmt.query_map([now], |row| {
                let bytes: Vec<u8> = row.get(0)?;
                let path: String = row.get(1)?;
                Ok((bytes, path))
            }) else {
                return;
            };
            let mut collected = Vec::new();
            for row in rows {
                let Ok((bytes, path)) = row else {
                    return;
                };
                let Ok(bytes) = <[u8; 16]>::try_from(bytes) else {
                    return;
                };
                collected.push((BatchId::from_bytes(bytes), path));
            }
            collected
        };
        for (batch_id, path) in expired_uploads {
            if tx.set_upload_state(batch_id, UploadState::Aborted).is_ok() {
                spools.push(path);
            }
        }
        if tx.commit().is_err() {
            return;
        }
        drop(db);
        remove_spools(self, spools);
    }
}

/// Mark every open upload of a lock aborted and return its spool paths.
pub(crate) fn abort_uploads(tx: &WriteTx<'_>, lock_id: LockId) -> Result<Vec<String>, Fault> {
    let mut paths = Vec::new();
    for upload in tx.uploads_for_lock(lock_id)? {
        if upload.state != UploadState::Aborted {
            tx.set_upload_state(upload.batch_id, UploadState::Aborted)?;
            paths.push(upload.spool_path);
        }
    }
    Ok(paths)
}

/// Check a lock for a mutation request.
pub(crate) fn check_lock<T: MmTx>(
    tx: &T,
    lock_id: LockId,
    session: SessionInfo,
    dir_path: &str,
) -> Result<LockRecord, Fault> {
    let Some(lock) = tx.lock(lock_id)? else {
        return Err(Fault::lock_lost("lock does not exist"));
    };
    if lock.owner_client != session.client_id {
        return Err(Fault::lock_lost("lock belongs to another client"));
    }
    if lock.dir_path != dir_path {
        return Err(Fault::lock_lost("lock belongs to another directory"));
    }
    if lock.expires_at_ms < now_ms() {
        return Err(Fault::lock_expired(&lock));
    }
    Ok(lock)
}

fn granted(
    lock: &LockRecord,
    dir_path: &str,
    dir_version: [u8; 32],
    snapshot_seq: u64,
    ttl_ms: u64,
) -> LockGranted {
    LockGranted {
        lock_id: *lock.lock_id.as_bytes(),
        dir_path: dir_path.to_owned(),
        dir_ino: lock.dir_ino,
        epoch: lock.base_epoch,
        base_seq: lock.base_seq.get(),
        snapshot_seq,
        dir_version,
        expires_at_ms: u64::try_from(lock.expires_at_ms).unwrap_or(u64::MAX),
        ttl_ms: u32::try_from(ttl_ms).unwrap_or(u32::MAX),
    }
}

pub(crate) fn remove_spools(state: &ServerState, paths: Vec<String>) {
    for path in paths {
        state.spool().remove_path(&path);
    }
}

// Keep the sequence type's role explicit: a lock stores a per-directory
// `dir_seq`, never the global `mm_seq`.
const _: fn(DirSeq) = |value| {
    let _ = value.get();
};
