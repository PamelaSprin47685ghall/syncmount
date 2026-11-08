//! Reconcile upload batches left by an earlier process.
//!
//! A crash after `COMMIT` reached the server but before the local commit
//! transaction leaves a committed batch id in `shadow_dirs` and the dirty
//! generations still set. The next [`Shadow::open`] asks the server about each
//! persisted id and adopts a committed result instead of uploading it again.
//!
//! The same reconciliation runs before a new upload, so a lost commit answer
//! is repaired on the next `fsync` rather than duplicated. A batch that is
//! still open is never resent: its staging directory did not survive the
//! restart, so the next `fsync` begins a new batch. A transport failure leaves
//! the row untouched and never blocks the mount.

use crate::mmap::types::MmBase;

use super::db::UploadPhase;
use super::remote::{BatchState, RemoteError};
use super::{Shadow, ShadowDir, ShadowError};

/// What reconciling one persisted batch did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BatchRecovery {
    /// The commit was adopted as the new base; no upload is needed.
    Adopted,
    /// The server still holds the batch; the caller must not resend it.
    Open,
    /// The batch was aborted or unknown; its id is gone.
    Abandoned,
}

impl Shadow {
    /// Reconcile every batch id persisted by an earlier process.
    ///
    /// Only a local database failure aborts the mount. A remote that cannot
    /// answer leaves the row untouched, so the next `fsync` retries.
    pub(super) fn recover_batches(&self) -> Result<(), ShadowError> {
        for dir in self.db.shadow_dirs()? {
            if dir.batch_id.is_none() {
                continue;
            }
            match self.reconcile_batch(&dir) {
                Ok(_) => {}
                Err(ShadowError::Remote(_)) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Reconcile one directory's persisted batch.
    ///
    /// Returns an error only for local failures and remote transport or
    /// authentication failures; the caller keeps the persisted state in that
    /// case.
    pub(super) fn reconcile_batch(&self, dir: &ShadowDir) -> Result<BatchRecovery, ShadowError> {
        let Some(batch_id) = dir.batch_id else {
            return Ok(BatchRecovery::Abandoned);
        };
        let status = match self.remote.batch_status(batch_id) {
            Ok(status) => status,
            Err(RemoteError::NotFound) => {
                self.abandon_batch(dir)?;
                return Ok(BatchRecovery::Abandoned);
            }
            Err(error) => return Err(error.into()),
        };
        if status.batch_id != batch_id {
            // A reply for another batch cannot be trusted; keep the row for
            // the next attempt.
            return Ok(BatchRecovery::Open);
        }
        match status.state {
            BatchState::Committed => {
                let (Some(snapshot_seq), Some(base_seq), Some(dir_version)) = (
                    status.snapshot_seq,
                    status.base_seq_after,
                    status.dir_version_after,
                ) else {
                    // A committed answer without its result violates the
                    // contract; keep the row and retry.
                    return Ok(BatchRecovery::Open);
                };
                if snapshot_seq <= dir.snapshot_seq {
                    // A checkout already saw this commit or a newer one. The
                    // batch must not roll the directory back; keep the dirty
                    // generations for the next fsync.
                    self.abandon_batch(dir)?;
                    return Ok(BatchRecovery::Abandoned);
                }
                // A commit never changes the database epoch, so the adopted
                // base keeps the epoch of the base the batch was built on.
                let base = MmBase::new(dir.record.base.epoch.max(1), base_seq, dir_version);
                let valid_until_ms = super::now_ms()
                    .saturating_add(i64::try_from(self.ttl.as_millis()).unwrap_or(i64::MAX));
                let adopted = self.db.publish_committed(
                    dir.record.ino,
                    base,
                    snapshot_seq,
                    dir.snapshot_gen,
                    valid_until_ms,
                    None,
                )?;
                if adopted {
                    Ok(BatchRecovery::Adopted)
                } else {
                    // A checkout already recorded this commit or a newer one.
                    Ok(BatchRecovery::Abandoned)
                }
            }
            BatchState::Open => Ok(BatchRecovery::Open),
            BatchState::Aborted => {
                self.abandon_batch(dir)?;
                Ok(BatchRecovery::Abandoned)
            }
        }
    }

    /// Drop one batch id and keep the dirty generations.
    fn abandon_batch(&self, dir: &ShadowDir) -> Result<(), ShadowError> {
        let phase = if dir.clean() {
            UploadPhase::Idle
        } else {
            UploadPhase::Dirty
        };
        self.db.clear_batch(dir.record.ino, phase)
    }
}
