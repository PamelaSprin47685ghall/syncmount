//! Userspace write-back buffer for the FUSE view.
//!
//! A `write` callback appends to a per-inode buffer and returns. The buffer is
//! committed to SQLite by [`WriteBuffer::commit`]. A synchronous commit comes
//! from `flush`, `fsync`, `release` and every namespace mutation; otherwise a
//! background thread commits within one [`WritebackConfig::flush_interval`].
//!
//! # Wake-up
//!
//! The background thread is event driven. A buffered write wakes it, and it
//! sets one commit deadline [`WritebackConfig::flush_interval`] later. It then
//! waits on a condition variable. An idle buffer produces no wake-up, so the
//! thread does not poll. `stop` wakes the thread, and the thread returns at
//! once.
//!
//! # Why userspace
//!
//! The kernel offers `FUSE_WRITEBACK_CACHE`, and fuser 0.18 can request it.
//! This filesystem deliberately does not: it opens files with
//! `FOPEN_DIRECT_IO` so a remote event can never leave a stale page in the
//! kernel cache. Writeback caching requires the page cache, and would then
//! need reverse invalidation from the replay thread. That invalidation waits
//! for dirty-page writeback while the replay thread holds the SQLite writer,
//! which is a deadlock shape. A userspace buffer keeps the existing read
//! semantics and still removes SQLite from the write syscall.
//!
//! # Ordering
//!
//! A buffered write is committed after any remote event that arrives in the
//! same window, because its outbox sequence is allocated at commit time. The
//! local write therefore wins for overlapping ranges, which is the same
//! last-writer-wins rule the server applies. If the object was deleted
//! remotely, the buffered data has no home and is discarded with a warning.
//!
//! # Crash window
//!
//! Data in the buffer is volatile. A process crash loses every write that has
//! not been committed; `fsync`, `flush`, `release`, a namespace mutation or
//! the background interval closes that window. The accepted semantics are
//! documented in `README.md` and `docs/known-limitations.md`.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{
    Arc, Condvar, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard, Weak,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::client::db::{CHUNK, ClientDb, DbError, Ino};
use crate::store::Errno;
use crate::store::sqlite::Object;

/// Default delay between background commits.
pub const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_millis(100);

/// Default cap on buffered bytes.
///
/// The cap is soft: a single large write is always accepted. When the total
/// exceeds it, the write path commits synchronously and logs a warning. It
/// never returns `ENOSPC`.
pub const DEFAULT_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Tuning for the write-back buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WritebackConfig {
    /// Maximum delay between a buffered write and its background commit.
    pub flush_interval: Duration,
    /// Soft cap on buffered bytes.
    pub max_bytes: usize,
}

impl Default for WritebackConfig {
    fn default() -> Self {
        Self {
            flush_interval: DEFAULT_FLUSH_INTERVAL,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}

impl WritebackConfig {
    /// Clamp zero values to a usable minimum.
    fn normalized(self) -> Self {
        Self {
            flush_interval: self.flush_interval.max(Duration::from_millis(1)),
            max_bytes: self.max_bytes.max(4096),
        }
    }
}

/// Observable state of the write-back buffer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WritebackStats {
    /// Bytes currently held in memory (dirty plus committing).
    pub buffered_bytes: u64,
    /// Largest value `buffered_bytes` has reached.
    pub peak_bytes: u64,
    /// Inode commits performed by the buffer.
    pub commits: u64,
    /// Explicit `flush`/`fsync` calls that reached the buffer.
    pub flushes: u64,
    /// Times the soft cap forced a synchronous commit.
    pub cap_hits: u64,
    /// Bytes discarded because their object was deleted or replaced.
    pub dropped_bytes: u64,
    /// Failed inode commits (retried later).
    pub commit_errors: u64,
}

/// A non-overlapping byte-range map for one inode.
///
/// Adjacent appends extend the last vector in place. An interior write splits
/// the range it covers, so inserting is proportional to the bytes written,
/// not to the size of the file.
#[derive(Clone, Debug, Default)]
pub(crate) struct InodeBuffer {
    segments: BTreeMap<u64, Vec<u8>>,
    end: u64,
    bytes: usize,
}

impl InodeBuffer {
    /// Insert or replace one byte range.
    pub(crate) fn insert(&mut self, off: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let end = off.saturating_add(data.len() as u64);

        // The common case: sequential appends extend the last segment.
        if let Some((&last_off, last)) = self.segments.iter_mut().next_back() {
            let last_end = last_off.saturating_add(last.len() as u64);
            if last_end == off {
                last.extend_from_slice(data);
                self.bytes += data.len();
                self.end = self.end.max(end);
                return;
            }
        }

        // A write immediately before the first segment.
        if let Some((&first_off, _)) = self.segments.iter().next() {
            if end == first_off {
                self.segments.insert(off, data.to_vec());
                self.bytes += data.len();
                self.end = self.end.max(end);
                return;
            }
        }

        // Split any segment the new range intersects, then insert.
        let keys: Vec<u64> = self
            .segments
            .range(..end)
            .filter(|(start, bytes)| start.saturating_add(bytes.len() as u64) > off)
            .map(|(&start, _)| start)
            .collect();
        let mut removed = 0usize;
        for key in keys {
            let Some(segment) = self.segments.remove(&key) else {
                continue;
            };
            let segment_end = key.saturating_add(segment.len() as u64);
            let overlap_start = key.max(off);
            let overlap_end = segment_end.min(end);
            if overlap_end > overlap_start {
                removed += (overlap_end - overlap_start) as usize;
            }
            if key < off {
                let keep = (off - key) as usize;
                self.segments.insert(key, segment[..keep].to_vec());
            }
            if segment_end > end {
                let skip = (end - key) as usize;
                self.segments.insert(end, segment[skip..].to_vec());
            }
        }
        self.segments.insert(off, data.to_vec());
        self.bytes = self
            .bytes
            .saturating_sub(removed)
            .saturating_add(data.len());
        self.end = self.end.max(end);
    }

    /// Copy the buffered bytes that fall inside `[off, off + dst.len())`.
    pub(crate) fn overlay(&self, off: u64, dst: &mut [u8]) {
        if dst.is_empty() {
            return;
        }
        let end = off.saturating_add(dst.len() as u64);
        for (&start, bytes) in self.segments.range(..end) {
            let segment_end = start.saturating_add(bytes.len() as u64);
            if segment_end <= off {
                continue;
            }
            let copy_start = start.max(off);
            let copy_end = segment_end.min(end);
            let from = (copy_start - start) as usize;
            let to = (copy_end - start) as usize;
            let at = (copy_start - off) as usize;
            dst[at..at + (to - from)].copy_from_slice(&bytes[from..to]);
        }
    }

    /// Merge an older buffer underneath this one. Overlapping newer bytes win.
    fn merge_under(self, older: Self) -> Self {
        let mut merged = older;
        for (off, data) in self.segments {
            merged.insert(off, &data);
        }
        merged
    }

    /// Byte ranges, in offset order.
    pub(crate) fn segments(&self) -> impl Iterator<Item = (u64, &[u8])> + '_ {
        self.segments
            .iter()
            .map(|(&off, data)| (off, data.as_slice()))
    }

    /// One past the highest written offset.
    pub(crate) fn end(&self) -> u64 {
        self.end
    }

    /// Bytes held by this buffer.
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    /// Whether the buffer holds no data.
    pub(crate) fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }
}

/// Shared buffer state. The read lock is held across the SQLite read in
/// `read_at`/`getattr`, so a commit that removes its data is ordered against
/// readers: a reader either sees the committing copy or reads the committed
/// database, never neither.
#[derive(Debug, Default)]
pub(crate) struct State {
    dirty: HashMap<Ino, InodeBuffer>,
    committing: HashMap<Ino, Arc<InodeBuffer>>,
    bytes: usize,
}

impl State {
    fn recompute_bytes(&mut self) {
        self.bytes = self.dirty.values().map(InodeBuffer::bytes).sum::<usize>()
            + self
                .committing
                .values()
                .map(|buffer| buffer.bytes())
                .sum::<usize>();
    }

    fn size(&self, ino: Ino) -> u64 {
        let committing = self.committing.get(&ino).map_or(0, |buffer| buffer.end());
        let dirty = self.dirty.get(&ino).map_or(0, |buffer| buffer.end());
        committing.max(dirty)
    }

    /// Report the buffered size for one object.
    pub(crate) fn overlay_object(&self, ino: Ino, object: &mut Object) {
        let end = self.size(ino);
        if end > object.size {
            object.size = end;
            object.block_count = u32::try_from(end.div_ceil(CHUNK)).unwrap_or(u32::MAX);
        }
    }

    /// Extend and overlay one SQLite read.
    pub(crate) fn overlay_read(&self, ino: Ino, off: u64, len: u32, data: &mut Vec<u8>) {
        let database_end = off.saturating_add(data.len() as u64);
        let wanted_end = off.saturating_add(u64::from(len));
        let buffered_end = self.size(ino);
        let target_end = wanted_end.min(buffered_end.max(database_end));
        if target_end > database_end {
            data.resize((target_end - off) as usize, 0);
        }
        if data.is_empty() {
            return;
        }
        if let Some(buffer) = self.committing.get(&ino) {
            buffer.overlay(off, data);
        }
        if let Some(buffer) = self.dirty.get(&ino) {
            buffer.overlay(off, data);
        }
    }
}

/// Wake-up state shared with the background committer.
///
/// `dirty` means that a buffered write may not be in SQLite yet. `insert` sets
/// it, and a failed commit sets it again. A successful commit clears it only
/// when `generation` did not change during the commit, so a write that arrives
/// while the commit runs cannot lose its wake-up. `stopped` ends the thread.
#[derive(Debug, Default)]
struct WaitState {
    dirty: bool,
    stopped: bool,
    generation: u64,
}

/// The write-back buffer.
pub(crate) struct WriteBuffer {
    state: RwLock<State>,
    commit: Mutex<()>,
    /// Wake-up state for the background committer. The thread owns clones of
    /// both `wait` and `wake`, so it can sleep without an `Arc<ClientDb>`.
    wait: Arc<Mutex<WaitState>>,
    wake: Arc<Condvar>,
    config: WritebackConfig,
    thread: Mutex<Option<JoinHandle<()>>>,
    peak: AtomicU64,
    commits: AtomicU64,
    flushes: AtomicU64,
    cap_hits: AtomicU64,
    dropped_bytes: AtomicU64,
    commit_errors: AtomicU64,
}

impl std::fmt::Debug for WriteBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteBuffer")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl WriteBuffer {
    /// Build an idle buffer.
    pub(crate) fn new(config: WritebackConfig) -> Self {
        Self {
            state: RwLock::new(State::default()),
            commit: Mutex::new(()),
            wait: Arc::new(Mutex::new(WaitState::default())),
            wake: Arc::new(Condvar::new()),
            config: config.normalized(),
            thread: Mutex::new(None),
            peak: AtomicU64::new(0),
            commits: AtomicU64::new(0),
            flushes: AtomicU64::new(0),
            cap_hits: AtomicU64::new(0),
            dropped_bytes: AtomicU64::new(0),
            commit_errors: AtomicU64::new(0),
        }
    }

    /// The effective configuration.
    pub(crate) fn config(&self) -> WritebackConfig {
        self.config
    }

    fn read_state(&self) -> RwLockReadGuard<'_, State> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Read guard for the read path. It must stay held across the SQLite
    /// snapshot; see [`State`].
    pub(crate) fn state_read(&self) -> RwLockReadGuard<'_, State> {
        self.read_state()
    }

    fn write_state(&self) -> RwLockWriteGuard<'_, State> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }

    fn commit_guard(&self) -> MutexGuard<'_, ()> {
        self.commit.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wait_state(&self) -> MutexGuard<'_, WaitState> {
        self.wait.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Current dirty generation, taken before a commit. [`Self::settle_dirty`]
    /// clears the flag only when this value is still current.
    fn dirty_generation(&self) -> u64 {
        self.wait_state().generation
    }

    /// Mark buffered data as pending and wake the background committer.
    ///
    /// The wake-up is sent only on a clean-to-dirty transition. When `dirty`
    /// is already set, the thread has already seen the work, or it will see it
    /// at its armed deadline. Extra wake-ups would only make it recheck sooner.
    fn mark_dirty(&self) {
        let mut wait = self.wait_state();
        let was_dirty = wait.dirty;
        wait.dirty = true;
        wait.generation = wait.generation.wrapping_add(1);
        drop(wait);
        if !was_dirty {
            self.wake.notify_one();
        }
    }

    /// Clear `dirty` after a successful commit.
    ///
    /// The flag stays set when data is still buffered, or when a write arrived
    /// after `generation` was taken. In both cases the next commit owns the
    /// remaining work.
    fn settle_dirty(&self, generation: u64) {
        // Read and release the state lock first: the wait lock must never nest
        // with the state lock.
        let leftover = {
            let state = self.read_state();
            !state.dirty.is_empty() || !state.committing.is_empty()
        };
        if leftover {
            return;
        }
        let mut wait = self.wait_state();
        if wait.generation == generation {
            wait.dirty = false;
        }
    }

    /// Append one write. Returns `true` when the soft cap is exceeded.
    pub(crate) fn insert(&self, ino: Ino, off: u64, data: &[u8]) -> bool {
        let mut state = self.write_state();
        let buffer = state.dirty.entry(ino).or_default();
        let before = buffer.bytes();
        buffer.insert(off, data);
        let after = buffer.bytes();
        state.bytes = state.bytes.saturating_sub(before).saturating_add(after);
        let bytes = state.bytes;
        drop(state);
        // Wake after the state lock is released, so the wait lock never nests
        // with the state lock.
        if !data.is_empty() {
            self.mark_dirty();
        }
        self.peak.fetch_max(bytes as u64, Ordering::Relaxed);
        bytes > self.config.max_bytes
    }

    /// Count one soft-cap event.
    pub(crate) fn note_cap_hit(&self) {
        self.cap_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Current observable state.
    pub(crate) fn stats(&self) -> WritebackStats {
        let buffered_bytes = self.read_state().bytes as u64;
        WritebackStats {
            buffered_bytes,
            peak_bytes: self.peak.load(Ordering::Relaxed),
            commits: self.commits.load(Ordering::Relaxed),
            flushes: self.flushes.load(Ordering::Relaxed),
            cap_hits: self.cap_hits.load(Ordering::Relaxed),
            dropped_bytes: self.dropped_bytes.load(Ordering::Relaxed),
            commit_errors: self.commit_errors.load(Ordering::Relaxed),
        }
    }

    /// Start the background committer.
    pub(crate) fn start(&self, db: &Arc<ClientDb>) {
        let mut slot = self.thread.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_some() {
            return;
        }
        let weak = Arc::downgrade(db);
        let wait = Arc::clone(&self.wait);
        let wake = Arc::clone(&self.wake);
        let interval = self.config.flush_interval;
        match std::thread::Builder::new()
            .name("syncmount-writeback".to_owned())
            .spawn(move || writeback_loop(weak, wait, wake, interval))
        {
            Ok(handle) => *slot = Some(handle),
            Err(error) => {
                tracing::warn!(
                    event = "writeback_spawn",
                    error = %error,
                    "cannot start the write-back thread"
                );
            }
        }
    }

    /// Stop and join the background committer.
    ///
    /// The thread wakes at once, even when it waits for a commit deadline.
    pub(crate) fn stop(&self) {
        {
            let mut wait = self.wait_state();
            wait.stopped = true;
        }
        self.wake.notify_all();
        let handle = {
            let mut slot = self.thread.lock().unwrap_or_else(PoisonError::into_inner);
            slot.take()
        };
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }

    /// Commit every dirty buffer.
    pub(crate) fn flush_all(&self, db: &ClientDb) -> Result<(), DbError> {
        self.flushes.fetch_add(1, Ordering::Relaxed);
        self.commit(db, None)
    }

    /// Commit every dirty buffer for the background thread (no flush count).
    pub(crate) fn flush_pending(&self, db: &ClientDb) -> Result<(), DbError> {
        self.commit(db, None)
    }

    /// Commit one inode's dirty buffer.
    pub(crate) fn flush_ino(&self, db: &ClientDb, ino: Ino) -> Result<(), DbError> {
        self.flushes.fetch_add(1, Ordering::Relaxed);
        self.commit(db, Some(ino))
    }

    /// Move dirty data into the committing set and write it to SQLite.
    ///
    /// `only = None` commits every inode. A failed inode stays in
    /// `committing` and is retried by the next call; the others still commit.
    ///
    /// The wake-up flag is settled after [`Self::commit_locked`] releases the
    /// commit guard and the state lock, so the wait lock never nests with
    /// either of them.
    fn commit(&self, db: &ClientDb, only: Option<Ino>) -> Result<(), DbError> {
        // Taken before the commit starts: every write that arrives later
        // raises the generation, so this commit cannot clear its pending flag.
        let generation = self.dirty_generation();
        let result = self.commit_locked(db, only);
        match &result {
            Ok(()) => self.settle_dirty(generation),
            Err(_) => self.mark_dirty(),
        }
        result
    }

    /// The body of [`Self::commit`], with the commit guard held.
    fn commit_locked(&self, db: &ClientDb, only: Option<Ino>) -> Result<(), DbError> {
        let _guard = self.commit_guard();
        {
            let mut state = self.write_state();
            let moved: Vec<(Ino, InodeBuffer)> = match only {
                Some(ino) => state
                    .dirty
                    .remove(&ino)
                    .map(|buffer| (ino, buffer))
                    .into_iter()
                    .collect(),
                None => state.dirty.drain().collect(),
            };
            for (ino, buffer) in moved {
                if buffer.is_empty() {
                    continue;
                }
                let merged = match state.committing.remove(&ino) {
                    Some(older) => buffer.merge_under(Arc::unwrap_or_clone(older)),
                    None => buffer,
                };
                state.committing.insert(ino, Arc::new(merged));
            }
            state.recompute_bytes();
        }

        let mut batch: Vec<(Ino, Arc<InodeBuffer>)> = {
            let state = self.read_state();
            match only {
                Some(ino) => state
                    .committing
                    .get(&ino)
                    .map(|buffer| (ino, Arc::clone(buffer)))
                    .into_iter()
                    .collect(),
                None => state
                    .committing
                    .iter()
                    .map(|(&ino, buffer)| (ino, Arc::clone(buffer)))
                    .collect(),
            }
        };
        if batch.is_empty() {
            return Ok(());
        }
        batch.sort_by_key(|(ino, _)| *ino);

        let refs: Vec<(Ino, &InodeBuffer)> = batch
            .iter()
            .map(|(ino, buffer)| (*ino, buffer.as_ref()))
            .collect();
        match db.commit_buffered_batch(&refs) {
            Ok(()) => {
                let mut state = self.write_state();
                for (ino, _) in &batch {
                    if let Some(removed) = state.committing.remove(ino) {
                        state.bytes = state.bytes.saturating_sub(removed.bytes());
                    }
                }
                self.commits
                    .fetch_add(batch.len() as u64, Ordering::Relaxed);
            }
            Err(error) if is_discardable(&error) => {
                let mut state = self.write_state();
                for (ino, _) in &batch {
                    if let Some(dropped) = state.committing.remove(ino) {
                        state.bytes = state.bytes.saturating_sub(dropped.bytes());
                        self.dropped_bytes
                            .fetch_add(dropped.bytes() as u64, Ordering::Relaxed);
                    }
                }
                tracing::warn!(
                    event = "writeback_discard",
                    error = %error,
                    "buffered batch discarded because an object is gone"
                );
            }
            Err(error) => {
                self.commit_errors.fetch_add(1, Ordering::Relaxed);
                return Err(error);
            }
        }
        Ok(())
    }

    /// Drop every buffered byte without committing it.
    ///
    /// Models a process crash at the buffer boundary: the next open sees only
    /// what was already committed.
    #[cfg(test)]
    pub(crate) fn abandon(&self) {
        let mut state = self.write_state();
        state.dirty.clear();
        state.committing.clear();
        state.bytes = 0;
        drop(state);
        let mut wait = self.wait_state();
        wait.dirty = false;
        wait.generation = wait.generation.wrapping_add(1);
    }
}

/// One inode commit either succeeded or the object cannot accept writes.
fn is_discardable(error: &DbError) -> bool {
    matches!(
        error,
        DbError::Errno(errno)
            if *errno == Errno::ENOENT || *errno == Errno::EISDIR || *errno == Errno::EINVAL
    )
}

/// Wait on `wake` until a notification, `stopped`, or `timeout` elapses.
///
/// `None` is an infinite wait; `Condvar::wait` is the std form of
/// `wait_timeout(None)`. The caller re-checks [`WaitState`] after every return.
fn wait_for<'a>(
    wake: &Condvar,
    guard: MutexGuard<'a, WaitState>,
    timeout: Option<Duration>,
) -> MutexGuard<'a, WaitState> {
    match timeout {
        Some(timeout) => {
            wake.wait_timeout(guard, timeout)
                .unwrap_or_else(PoisonError::into_inner)
                .0
        }
        None => wake.wait(guard).unwrap_or_else(PoisonError::into_inner),
    }
}

/// Background loop: commit one interval after a write, then sleep.
///
/// The thread holds no `Arc<ClientDb>` while it waits, so it cannot keep the
/// database alive. It wakes for three reasons only: a write, the commit
/// deadline, or [`WriteBuffer::stop`]. An idle buffer sleeps without a timer,
/// so it produces no wake-up and no commit.
fn writeback_loop(
    db: Weak<ClientDb>,
    wait: Arc<Mutex<WaitState>>,
    wake: Arc<Condvar>,
    interval: Duration,
) {
    let mut deadline: Option<Instant> = None;
    loop {
        let guard = wait.lock().unwrap_or_else(PoisonError::into_inner);
        if guard.stopped {
            return;
        }
        if !guard.dirty {
            // Nothing to commit. Wait for `insert` or `stop`; no timer runs.
            deadline = None;
            drop(wait_for(wake.as_ref(), guard, None));
            continue;
        }
        let now = Instant::now();
        let due = *deadline.get_or_insert(now + interval);
        if now < due {
            drop(wait_for(wake.as_ref(), guard, Some(due - now)));
            continue;
        }
        // The deadline is spent. Clear it before the commit, so a failure
        // waits one full interval before the retry instead of spinning.
        deadline = None;
        drop(guard);
        let Some(db) = db.upgrade() else {
            return;
        };
        if let Err(error) = db.commit_pending() {
            tracing::warn!(
                event = "writeback_commit",
                error = %error,
                "background write-back commit failed; will retry"
            );
        }
        drop(db);
        // `commit` clears `dirty` on success and sets it again on failure. A
        // write that arrives during the commit keeps it set. The next
        // iteration reads the result under the wait lock.
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::client::db::{ApplyOutcome, OutboxState};
    use crate::client::ops::{AttrChange, CreateAttrs};
    use crate::store::sqlite::{EventPayload, ROOT_INO};
    use std::ffi::OsStr;
    use std::sync::Arc;
    use std::time::Instant;

    fn open_with(config: WritebackConfig) -> (tempfile::TempDir, ClientDb) {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDb::open_with_writeback(dir.path().join("client.db"), [7u8; 16], config).unwrap();
        (dir, db)
    }

    fn open() -> (tempfile::TempDir, ClientDb) {
        open_with(WritebackConfig::default())
    }

    fn file(db: &ClientDb, name: &str) -> crate::store::sqlite::Object {
        db.create_file(
            ROOT_INO,
            OsStr::new(name),
            CreateAttrs::new(0o644, 1000, 1000),
        )
        .unwrap()
    }

    #[test]
    fn write_and_read_are_consistent_before_and_after_commit() {
        let (_dir, db) = open();
        let object = file(&db, "f");
        assert_eq!(db.write_at(object.ino, 0, b"hello").unwrap(), 5);
        assert_eq!(db.write_at(object.ino, 5, b" world").unwrap(), 6);
        // The volatile window: the bytes are visible to reads but not yet in
        // SQLite's outbox.
        assert_eq!(db.read_at(object.ino, 0, 11).unwrap(), b"hello world");
        assert_eq!(db.getattr(object.ino).unwrap().size, 11);
        assert_eq!(
            db.outbox_count(OutboxState::Pending).unwrap(),
            1,
            "only the create is committed"
        );
        assert!(db.writeback_stats().buffered_bytes >= 11);

        db.flush_all().unwrap();
        assert_eq!(db.outbox_count(OutboxState::Pending).unwrap(), 2);
        assert_eq!(db.writeback_stats().buffered_bytes, 0);
        assert_eq!(db.read_at(object.ino, 0, 11).unwrap(), b"hello world");
    }

    #[test]
    fn a_hole_reads_as_zeroes_and_later_writes_fill_it() {
        let (_dir, db) = open();
        let object = file(&db, "f");
        db.write_at(object.ino, 0, b"head").unwrap();
        db.write_at(object.ino, 70_000, b"tail").unwrap();
        let read = db.read_at(object.ino, 0, 70_004).unwrap();
        assert_eq!(&read[..4], b"head");
        assert!(read[4..70_000].iter().all(|byte| *byte == 0));
        assert_eq!(&read[70_000..], b"tail");
        db.flush_all().unwrap();
        assert_eq!(db.getattr(object.ino).unwrap().size, 70_004);
    }

    #[test]
    fn truncate_flushes_and_keeps_outbox_order() {
        let (_dir, db) = open();
        let object = file(&db, "f");
        db.write_at(object.ino, 0, b"0123456789").unwrap();
        db.truncate(object.ino, 4).unwrap();
        assert_eq!(db.getattr(object.ino).unwrap().size, 4);
        assert_eq!(db.read_at(object.ino, 0, 10).unwrap(), b"0123");
        let rows = db.outbox_page(10).unwrap();
        let kinds: Vec<&str> = rows.iter().map(|row| row.decoded.kind().as_str()).collect();
        assert_eq!(kinds, vec!["create_file", "write", "truncate"]);
    }

    #[test]
    fn unlink_flushes_the_file_first() {
        let (_dir, db) = open();
        let object = file(&db, "f");
        db.write_at(object.ino, 0, b"bye").unwrap();
        db.unlink(ROOT_INO, OsStr::new("f")).unwrap();
        assert!(db.lookup(ROOT_INO, OsStr::new("f")).is_err());
        let rows = db.outbox_page(10).unwrap();
        let kinds: Vec<&str> = rows.iter().map(|row| row.decoded.kind().as_str()).collect();
        assert_eq!(kinds, vec!["create_file", "write", "unlink"]);
    }

    #[test]
    fn rename_flushes_the_file_first() {
        let (_dir, db) = open();
        let object = file(&db, "f");
        db.write_at(object.ino, 0, b"moved").unwrap();
        db.rename(
            ROOT_INO,
            OsStr::new("f"),
            ROOT_INO,
            OsStr::new("g"),
            Default::default(),
        )
        .unwrap();
        assert_eq!(db.lookup_by_path("/g").unwrap().size, 5);
        assert_eq!(db.read_at(object.ino, 0, 5).unwrap(), b"moved");
        let rows = db.outbox_page(10).unwrap();
        let kinds: Vec<&str> = rows.iter().map(|row| row.decoded.kind().as_str()).collect();
        assert_eq!(kinds, vec!["create_file", "write", "rename"]);
    }

    #[test]
    fn an_abandoned_buffer_loses_only_uncommitted_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.db");
        let object_ino;
        {
            let db = ClientDb::open(&path, [7u8; 16]).unwrap();
            let object = file(&db, "f");
            object_ino = object.ino;
            db.write_at(object_ino, 0, b"committed").unwrap();
            db.flush_all().unwrap();
            db.write_at(object_ino, 9, b"volatile").unwrap();
            db.writeback().abandon();
            assert_eq!(db.read_at(object_ino, 0, 17).unwrap(), b"committed");
            // Dropping the database flushes nothing: the buffer was abandoned.
        }
        let reopened = ClientDb::open(&path, [7u8; 16]).unwrap();
        assert_eq!(reopened.read_at(object_ino, 0, 17).unwrap(), b"committed");
        assert_eq!(
            reopened.outbox_count(OutboxState::Pending).unwrap(),
            2,
            "create and committed write only"
        );
    }

    #[test]
    fn out_of_order_large_writes_survive_commit() {
        let (_dir, db) = open();
        let object = file(&db, "f");
        let mut expected = vec![0u8; 20 << 20];
        for chunk in (0..20u64).rev() {
            let offset = chunk << 20;
            let data: Vec<u8> = (0..1usize << 20)
                .map(|index| ((offset as usize + index) % 251) as u8)
                .collect();
            db.write_at(object.ino, offset, &data).unwrap();
            expected[(offset as usize)..(offset as usize + data.len())].copy_from_slice(&data);
        }
        db.flush_all().unwrap();
        let got = db
            .read_at(object.ino, 0, u32::try_from(expected.len()).unwrap())
            .unwrap();
        assert_eq!(got, expected);
    }

    fn run_kill_scenario(scenario: &str) -> (tempfile::TempDir, ClientDb) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("client.db");
        let ready = dir.path().join("ready");
        let exe = std::env::current_exe().unwrap();
        let mut child = std::process::Command::new(exe)
            .args([
                "--exact",
                "client::writeback::tests::kill_child",
                "--nocapture",
            ])
            .env("SYNCMOUNT_KILL_DB", &db_path)
            .env("SYNCMOUNT_KILL_READY", &ready)
            .env("SYNCMOUNT_KILL_SCENARIO", scenario)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            assert!(
                Instant::now() < deadline,
                "kill child for {scenario} did not become ready"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().unwrap();
        let status = child.wait().unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        let db = ClientDb::open(&db_path, [7u8; 16]).unwrap();
        (dir, db)
    }

    /// Child half of the `kill_9_*` tests. It commits the named operation,
    /// leaves one volatile write where the scenario asks for it, writes the
    /// readiness marker, and waits for SIGKILL.
    #[test]
    fn kill_child() {
        let (Ok(db_path), Ok(ready), Ok(scenario)) = (
            std::env::var("SYNCMOUNT_KILL_DB"),
            std::env::var("SYNCMOUNT_KILL_READY"),
            std::env::var("SYNCMOUNT_KILL_SCENARIO"),
        ) else {
            return;
        };
        let db = ClientDb::open(&db_path, [7u8; 16]).unwrap();
        match scenario.as_str() {
            "write" => {
                let object = file(&db, "f");
                db.write_at(object.ino, 0, b"committed").unwrap();
                db.flush_all().unwrap();
                db.write_at(object.ino, 9, b"volatile").unwrap();
            }
            "rename" => {
                let object = file(&db, "f");
                db.write_at(object.ino, 0, b"data").unwrap();
                db.flush_all().unwrap();
                db.rename(
                    ROOT_INO,
                    OsStr::new("f"),
                    ROOT_INO,
                    OsStr::new("g"),
                    Default::default(),
                )
                .unwrap();
                let moved = db.lookup(ROOT_INO, OsStr::new("g")).unwrap();
                db.write_at(moved.ino, 4, b"volatile").unwrap();
            }
            "rename_overwrite" => {
                let a = file(&db, "a");
                db.write_at(a.ino, 0, b"new").unwrap();
                db.flush_all().unwrap();
                let b = file(&db, "b");
                db.write_at(b.ino, 0, b"old").unwrap();
                db.flush_all().unwrap();
                db.rename(
                    ROOT_INO,
                    OsStr::new("a"),
                    ROOT_INO,
                    OsStr::new("b"),
                    Default::default(),
                )
                .unwrap();
            }
            "unlink" => {
                let object = file(&db, "f");
                db.write_at(object.ino, 0, b"data").unwrap();
                db.flush_all().unwrap();
                db.unlink(ROOT_INO, OsStr::new("f")).unwrap();
            }
            "truncate" => {
                let object = file(&db, "f");
                db.write_at(object.ino, 0, b"0123456789").unwrap();
                db.flush_all().unwrap();
                db.truncate(object.ino, 4).unwrap();
            }
            "setattr" => {
                let object = file(&db, "f");
                db.write_at(object.ino, 0, b"0123456789").unwrap();
                db.flush_all().unwrap();
                db.setattr(
                    object.ino,
                    AttrChange {
                        size: Some(4),
                        mode: Some(0o600),
                        ..AttrChange::default()
                    },
                )
                .unwrap();
            }
            other => panic!("unknown kill scenario {other}"),
        }
        std::fs::write(&ready, b"ready").unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn kill_9_after_flush_loses_only_the_volatile_write() {
        let (_dir, db) = run_kill_scenario("write");
        let object = db.lookup(ROOT_INO, OsStr::new("f")).unwrap();
        assert_eq!(object.size, 9);
        assert_eq!(db.read_at(object.ino, 0, 17).unwrap(), b"committed");
        assert_eq!(db.outbox_count(OutboxState::Pending).unwrap(), 2);
    }

    #[test]
    fn kill_9_rename_is_all_or_nothing() {
        let (_dir, db) = run_kill_scenario("rename");
        assert!(db.lookup(ROOT_INO, OsStr::new("f")).is_err());
        let object = db.lookup(ROOT_INO, OsStr::new("g")).unwrap();
        assert_eq!(object.size, 4, "the volatile write after rename is gone");
        assert_eq!(db.read_at(object.ino, 0, 8).unwrap(), b"data");
        let kinds: Vec<&str> = db
            .outbox_page(10)
            .unwrap()
            .iter()
            .map(|row| row.decoded.kind().as_str())
            .collect();
        assert_eq!(kinds, vec!["create_file", "write", "rename"]);
    }

    #[test]
    fn kill_9_rename_overwrite_is_all_or_nothing() {
        let (_dir, db) = run_kill_scenario("rename_overwrite");
        assert!(db.lookup(ROOT_INO, OsStr::new("a")).is_err());
        let object = db.lookup(ROOT_INO, OsStr::new("b")).unwrap();
        assert_eq!(object.size, 3);
        assert_eq!(db.read_at(object.ino, 0, 3).unwrap(), b"new");
        let kinds: Vec<&str> = db
            .outbox_page(20)
            .unwrap()
            .iter()
            .map(|row| row.decoded.kind().as_str())
            .collect();
        assert_eq!(
            kinds,
            vec!["create_file", "write", "create_file", "write", "rename"]
        );
    }

    #[test]
    fn kill_9_unlink_is_all_or_nothing() {
        let (_dir, db) = run_kill_scenario("unlink");
        assert!(db.lookup(ROOT_INO, OsStr::new("f")).is_err());
        let kinds: Vec<&str> = db
            .outbox_page(10)
            .unwrap()
            .iter()
            .map(|row| row.decoded.kind().as_str())
            .collect();
        assert_eq!(kinds, vec!["create_file", "write", "unlink"]);
    }

    #[test]
    fn kill_9_truncate_is_all_or_nothing() {
        let (_dir, db) = run_kill_scenario("truncate");
        let object = db.lookup(ROOT_INO, OsStr::new("f")).unwrap();
        assert_eq!(object.size, 4);
        assert_eq!(db.read_at(object.ino, 0, 10).unwrap(), b"0123");
        let kinds: Vec<&str> = db
            .outbox_page(10)
            .unwrap()
            .iter()
            .map(|row| row.decoded.kind().as_str())
            .collect();
        assert_eq!(kinds, vec!["create_file", "write", "truncate"]);
    }

    #[test]
    fn kill_9_setattr_size_and_mode_are_one_transaction() {
        let (_dir, db) = run_kill_scenario("setattr");
        let object = db.lookup(ROOT_INO, OsStr::new("f")).unwrap();
        assert_eq!(object.size, 4);
        assert_eq!(object.mode, 0o600);
        assert_eq!(db.read_at(object.ino, 0, 10).unwrap(), b"0123");
        let kinds: Vec<&str> = db
            .outbox_page(10)
            .unwrap()
            .iter()
            .map(|row| row.decoded.kind().as_str())
            .collect();
        assert_eq!(kinds, vec!["create_file", "write", "setattr"]);
        let row = db.outbox_page(10).unwrap().pop().expect("setattr row");
        match row.decoded {
            EventPayload::Setattr { size, mode, .. } => {
                assert_eq!(size, Some(4), "size is part of the one setattr event");
                assert_eq!(mode, Some(0o600), "mode is part of the same event");
            }
            other => panic!("last outbox row is {:?}", other.kind()),
        }
    }

    #[test]
    fn setattr_size_and_mode_are_one_outbox_event() {
        let (_dir, db) = open();
        let object = file(&db, "f");
        db.write_at(object.ino, 0, b"0123456789").unwrap();
        db.flush_all().unwrap();
        db.setattr(
            object.ino,
            AttrChange {
                size: Some(4),
                mode: Some(0o600),
                ..AttrChange::default()
            },
        )
        .unwrap();

        let rows = db.outbox_page(10).unwrap();
        let kinds: Vec<&str> = rows.iter().map(|row| row.decoded.kind().as_str()).collect();
        assert_eq!(kinds, vec!["create_file", "write", "setattr"]);
        match &rows.last().expect("setattr row").decoded {
            EventPayload::Setattr { size, mode, .. } => {
                assert_eq!(*size, Some(4));
                assert_eq!(*mode, Some(0o600));
            }
            other => panic!("last outbox row is {:?}", other.kind()),
        }
        let object = db.getattr(object.ino).unwrap();
        assert_eq!(object.size, 4);
        assert_eq!(object.mode, 0o600);
        assert_eq!(db.read_at(object.ino, 0, 10).unwrap(), b"0123");
    }

    #[test]
    fn an_old_own_echo_does_not_shrink_newer_local_writes() {
        let (_dir, db) = open();
        let object = file(&db, "f");
        let first = vec![1u8; 1 << 20];
        let second = vec![2u8; 1 << 20];
        db.write_at(object.ino, 0, &first).unwrap();
        db.flush_all().unwrap();
        db.write_at(object.ino, 1 << 20, &second).unwrap();
        db.flush_all().unwrap();

        let rows = db.outbox_page(10).unwrap();
        let write_a = rows
            .iter()
            .find(|row| matches!(row.decoded, EventPayload::Write { offset: 0, .. }))
            .unwrap()
            .clone();
        let mut data = Vec::new();
        for chunk in db.outbox_chunks(write_a.op_id).unwrap() {
            data.extend_from_slice(chunk.data.as_deref().unwrap());
        }
        let epoch = db.epoch().unwrap();
        let outcome = db
            .apply_remote(
                1,
                epoch,
                Some(write_a.op_id),
                "ok",
                &write_a.decoded,
                write_a.path.as_deref(),
                None,
                Some(&data),
            )
            .unwrap();
        assert_eq!(outcome, ApplyOutcome::Applied);
        assert_eq!(
            db.getattr(object.ino).unwrap().size,
            2 << 20,
            "an old echo must not shrink the newer local file"
        );
        assert_eq!(db.read_at(object.ino, 1 << 20, 1 << 20).unwrap(), second);
    }

    #[test]
    fn large_sequential_writes_survive_a_background_commit() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(
            ClientDb::open_with_writeback(
                dir.path().join("client.db"),
                [7u8; 16],
                WritebackConfig {
                    flush_interval: Duration::from_millis(10),
                    ..WritebackConfig::default()
                },
            )
            .unwrap(),
        );
        db.start_writeback();
        let object = file(&db, "f");
        let mut expected = Vec::new();
        let mut offset = 0u64;
        for _ in 0..20 {
            let data: Vec<u8> = (0..1usize << 20)
                .map(|index| ((offset as usize + index) % 251) as u8)
                .collect();
            db.write_at(object.ino, offset, &data).unwrap();
            expected.extend_from_slice(&data);
            offset += data.len() as u64;
        }
        db.fsync().unwrap();
        let got = db
            .read_at(object.ino, 0, u32::try_from(offset).unwrap())
            .unwrap();
        assert_eq!(got.len(), expected.len());
        assert_eq!(got, expected);
        db.stop_writeback();
    }

    #[test]
    fn a_killed_process_loses_only_uncommitted_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.db");
        let exe = std::env::current_exe().unwrap();
        let status = std::process::Command::new(exe)
            .args([
                "--exact",
                "client::writeback::tests::crash_child",
                "--nocapture",
            ])
            .env("SYNCMOUNT_CRASH_DB", &path)
            .status()
            .unwrap();
        assert!(
            !status.success(),
            "the child must die without running ClientDb::drop"
        );
        let reopened = ClientDb::open(&path, [7u8; 16]).unwrap();
        let object = reopened.lookup(ROOT_INO, OsStr::new("f")).unwrap();
        assert_eq!(object.size, 9, "only the committed write survives");
        assert_eq!(reopened.read_at(object.ino, 0, 17).unwrap(), b"committed");
        assert_eq!(reopened.outbox_count(OutboxState::Pending).unwrap(), 2);
    }

    /// Child half of [`a_killed_process_loses_only_uncommitted_writes`].
    /// Aborts without unwinding, so `ClientDb::drop` cannot flush.
    #[test]
    fn crash_child() {
        let Ok(path) = std::env::var("SYNCMOUNT_CRASH_DB") else {
            return;
        };
        let db = ClientDb::open(&path, [7u8; 16]).unwrap();
        let object = file(&db, "f");
        db.write_at(object.ino, 0, b"committed").unwrap();
        db.flush_all().unwrap();
        db.write_at(object.ino, 9, b"volatile").unwrap();
        std::process::abort();
    }

    #[test]
    fn the_background_thread_commits_within_the_interval() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(
            ClientDb::open_with_writeback(
                dir.path().join("client.db"),
                [7u8; 16],
                WritebackConfig {
                    flush_interval: Duration::from_millis(50),
                    ..WritebackConfig::default()
                },
            )
            .unwrap(),
        );
        db.start_writeback();
        let object = file(&db, "f");
        db.write_at(object.ino, 0, b"timer").unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while db.outbox_count(OutboxState::Pending).unwrap() < 2 {
            assert!(Instant::now() < deadline, "background commit did not run");
            std::thread::sleep(Duration::from_millis(10));
        }
        db.stop_writeback();
        assert_eq!(db.read_at(object.ino, 0, 5).unwrap(), b"timer");
    }

    fn open_shared(interval: Duration) -> (tempfile::TempDir, Arc<ClientDb>) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(
            ClientDb::open_with_writeback(
                dir.path().join("client.db"),
                [7u8; 16],
                WritebackConfig {
                    flush_interval: interval,
                    ..WritebackConfig::default()
                },
            )
            .unwrap(),
        );
        (dir, db)
    }

    #[test]
    fn a_buffered_write_commits_only_after_the_interval() {
        let (_dir, db) = open_shared(Duration::from_millis(500));
        db.start_writeback();
        let object = file(&db, "f");
        db.write_at(object.ino, 0, b"later").unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            db.writeback_stats().commits,
            0,
            "the background thread must wait for the flush interval"
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        while db.writeback_stats().commits == 0 {
            assert!(
                Instant::now() < deadline,
                "the background thread did not commit after the interval"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        db.stop_writeback();
        assert_eq!(db.read_at(object.ino, 0, 5).unwrap(), b"later");
        assert_eq!(db.outbox_count(OutboxState::Pending).unwrap(), 2);
    }

    #[test]
    fn an_idle_buffer_stops_without_waiting_for_the_interval() {
        let (_dir, db) = open_shared(Duration::from_secs(60));
        db.start_writeback();
        let started = Instant::now();
        db.stop_writeback();
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "stop must wake the idle thread and not wait for the interval"
        );
    }

    #[test]
    fn an_idle_background_thread_does_not_commit_periodically() {
        let (_dir, db) = open_shared(Duration::from_millis(20));
        db.start_writeback();
        // Five intervals without a write. The thread must stay asleep.
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            db.writeback_stats().commits,
            0,
            "an idle buffer has nothing to commit"
        );
        let object = file(&db, "f");
        db.write_at(object.ino, 0, b"once").unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while db.writeback_stats().commits == 0 {
            assert!(
                Instant::now() < deadline,
                "the buffered write was not committed"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let commits = db.writeback_stats().commits;
        // After the queue drains, no periodic commit may run.
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            db.writeback_stats().commits,
            commits,
            "an idle background thread must not commit on a timer"
        );
        // A write after the idle period must wake the thread again.
        db.write_at(object.ino, 4, b"twice").unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while db.writeback_stats().commits <= commits {
            assert!(
                Instant::now() < deadline,
                "a later write did not wake the background thread"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        db.stop_writeback();
    }

    #[test]
    fn a_small_cap_commits_synchronously_without_enospc() {
        let (_dir, db) = open_with(WritebackConfig {
            flush_interval: Duration::from_secs(60),
            max_bytes: 4096,
        });
        let object = file(&db, "f");
        let data = vec![7u8; 8192];
        assert_eq!(db.write_at(object.ino, 0, &data).unwrap(), data.len());
        assert_eq!(db.writeback_stats().cap_hits, 1);
        assert_eq!(db.writeback_stats().buffered_bytes, 0);
        assert_eq!(db.outbox_count(OutboxState::Pending).unwrap(), 2);
    }
}
