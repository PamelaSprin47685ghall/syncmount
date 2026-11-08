//! Local advisory locks.
//!
//! POSIX `fcntl` locks are emulated in the daemon over `shadow` inodes. The
//! kernel has one mount and one daemon, so this table is the same-host
//! authority for every application process. `flock` is left to the kernel
//! (the mount does not advertise `FUSE_FLOCK_LOCKS`); [`flock_exclusive`]
//! exists for code that opens a shadow object directly.
//!
//! Cross-machine advisory locks are deliberately not shared. The upload lease
//! in [`super::remote`] is a different mechanism and never blocks a user lock.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::Duration;

use rustix::fs::{FlockOperation, flock};

use crate::mmap::types::Ino;

use super::ShadowError;

/// One range lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeLock {
    pub owner: u64,
    pub start: u64,
    pub end: u64,
    pub typ: i32,
    pub pid: u32,
}

impl RangeLock {
    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.start <= end && start <= self.end
    }
}

/// The daemon-wide POSIX lock table.
#[derive(Debug, Default)]
pub struct LockTable {
    locks: Mutex<HashMap<Ino, Vec<RangeLock>>>,
    changed: Condvar,
}

impl LockTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Test one range and return the first conflicting lock.
    pub fn getlk(
        &self,
        ino: Ino,
        owner: u64,
        start: u64,
        end: u64,
        typ: i32,
    ) -> Result<Option<RangeLock>, ShadowError> {
        if typ != libc::F_RDLCK && typ != libc::F_WRLCK {
            return Err(ShadowError::Invalid("lock type is not read or write"));
        }
        let locks = self.locks.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(locks.get(&ino).and_then(|entries| {
            entries
                .iter()
                .find(|entry| {
                    entry.owner != owner
                        && entry.overlaps(start, end)
                        && (typ == libc::F_WRLCK || entry.typ == libc::F_WRLCK)
                })
                .copied()
        }))
    }

    /// Apply one range lock. `sleep` waits until the conflict disappears.
    #[allow(clippy::too_many_arguments)]
    pub fn setlk(
        &self,
        ino: Ino,
        owner: u64,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
        sleep: bool,
    ) -> Result<(), ShadowError> {
        if !matches!(typ, libc::F_RDLCK | libc::F_WRLCK | libc::F_UNLCK) {
            return Err(ShadowError::Invalid("unknown lock type"));
        }
        let mut locks = self.locks.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if typ == libc::F_UNLCK {
                remove_range(&mut locks, ino, owner, start, end);
                self.changed.notify_all();
                return Ok(());
            }
            let conflict = locks.get(&ino).is_some_and(|entries| {
                entries.iter().any(|entry| {
                    entry.owner != owner
                        && entry.overlaps(start, end)
                        && (typ == libc::F_WRLCK || entry.typ == libc::F_WRLCK)
                })
            });
            if !conflict {
                remove_range(&mut locks, ino, owner, start, end);
                locks.entry(ino).or_default().push(RangeLock {
                    owner,
                    start,
                    end,
                    typ,
                    pid,
                });
                self.changed.notify_all();
                return Ok(());
            }
            if !sleep {
                return Err(ShadowError::Conflict);
            }
            let (next, timeout) = self
                .changed
                .wait_timeout(locks, Duration::from_millis(100))
                .unwrap_or_else(PoisonError::into_inner);
            locks = next;
            if timeout.timed_out() {
                // Re-check the table after every timeout so a released lock
                // is observed even when no notification reaches this waiter.
                continue;
            }
        }
    }

    /// Drop every lock owned by one open file description.
    pub fn release_owner(&self, ino: Ino, owner: u64) {
        let mut locks = self.locks.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entries) = locks.get_mut(&ino) {
            entries.retain(|entry| entry.owner != owner);
            if entries.is_empty() {
                locks.remove(&ino);
            }
        }
        self.changed.notify_all();
    }

    /// Drop every lock on one inode.
    pub fn release_ino(&self, ino: Ino) {
        let mut locks = self.locks.lock().unwrap_or_else(PoisonError::into_inner);
        locks.remove(&ino);
        self.changed.notify_all();
    }

    /// Number of live range entries; used by tests and diagnostics.
    pub fn len(&self) -> usize {
        self.locks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .map(Vec::len)
            .sum()
    }

    /// True when no range lock is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn remove_range(
    locks: &mut HashMap<Ino, Vec<RangeLock>>,
    ino: Ino,
    owner: u64,
    start: u64,
    end: u64,
) {
    let Some(entries) = locks.get_mut(&ino) else {
        return;
    };
    let mut kept = Vec::with_capacity(entries.len() + 2);
    for entry in entries.drain(..) {
        if entry.owner != owner || !entry.overlaps(start, end) {
            kept.push(entry);
            continue;
        }
        if entry.start < start {
            kept.push(RangeLock {
                end: start - 1,
                ..entry
            });
        }
        if entry.end > end {
            kept.push(RangeLock {
                start: end.saturating_add(1),
                ..entry
            });
        }
    }
    if kept.is_empty() {
        locks.remove(&ino);
    } else {
        *entries = kept;
    }
}

/// Take a BSD `flock` on one open shadow file.
///
/// This is the same lock the kernel would take for an application that opens
/// the shadow file directly. It is never used to emulate FUSE `flock`, which
/// the kernel keeps local because the mount does not advertise
/// `FUSE_FLOCK_LOCKS`.
pub fn flock_exclusive(file: &File, nonblocking: bool) -> io::Result<()> {
    let operation = if nonblocking {
        FlockOperation::NonBlockingLockExclusive
    } else {
        FlockOperation::LockExclusive
    };
    flock(file, operation).map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))
}

/// Take a shared BSD `flock`.
pub fn flock_shared(file: &File, nonblocking: bool) -> io::Result<()> {
    let operation = if nonblocking {
        FlockOperation::NonBlockingLockShared
    } else {
        FlockOperation::LockShared
    };
    flock(file, operation).map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn ino(value: u8) -> Ino {
        [value; 16]
    }

    #[test]
    fn write_lock_conflicts_with_another_owner() {
        let table = LockTable::new();
        table
            .setlk(ino(1), 7, 0, 99, libc::F_WRLCK, 10, false)
            .unwrap();
        assert!(matches!(
            table.setlk(ino(1), 8, 0, 99, libc::F_RDLCK, 11, false),
            Err(ShadowError::Conflict)
        ));
        assert!(
            table
                .getlk(ino(1), 8, 0, 99, libc::F_RDLCK)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn read_locks_share_and_write_excludes() {
        let table = LockTable::new();
        table
            .setlk(ino(2), 1, 0, 9, libc::F_RDLCK, 1, false)
            .unwrap();
        table
            .setlk(ino(2), 2, 0, 9, libc::F_RDLCK, 2, false)
            .unwrap();
        assert!(
            table
                .setlk(ino(2), 3, 0, 9, libc::F_WRLCK, 3, false)
                .is_err()
        );
        table
            .setlk(ino(2), 1, 0, 9, libc::F_UNLCK, 1, false)
            .unwrap();
        table
            .setlk(ino(2), 2, 0, 9, libc::F_UNLCK, 2, false)
            .unwrap();
        table
            .setlk(ino(2), 3, 0, 9, libc::F_WRLCK, 3, false)
            .unwrap();
    }

    #[test]
    fn unlock_splits_the_owner_range() {
        let table = LockTable::new();
        table
            .setlk(ino(3), 1, 0, 99, libc::F_WRLCK, 1, false)
            .unwrap();
        table
            .setlk(ino(3), 1, 20, 29, libc::F_UNLCK, 1, false)
            .unwrap();
        let locks = table.locks.lock().unwrap();
        let entries = locks.get(&ino(3)).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!((entries[0].start, entries[0].end), (0, 19));
        assert_eq!((entries[1].start, entries[1].end), (30, 99));
    }

    #[test]
    fn same_owner_replaces_its_own_range() {
        let table = LockTable::new();
        table
            .setlk(ino(4), 1, 0, 49, libc::F_WRLCK, 1, false)
            .unwrap();
        table
            .setlk(ino(4), 1, 25, 74, libc::F_RDLCK, 1, false)
            .unwrap();
        let locks = table.locks.lock().unwrap();
        let entries = locks.get(&ino(4)).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|entry| entry.owner == 1));
    }

    #[test]
    fn release_owner_drops_only_that_owner() {
        let table = LockTable::new();
        table
            .setlk(ino(5), 1, 0, 9, libc::F_RDLCK, 1, false)
            .unwrap();
        table
            .setlk(ino(5), 2, 0, 9, libc::F_RDLCK, 2, false)
            .unwrap();
        table.release_owner(ino(5), 1);
        assert_eq!(table.len(), 1);
        assert_eq!(
            table
                .getlk(ino(5), 3, 0, 9, libc::F_WRLCK)
                .unwrap()
                .unwrap()
                .owner,
            2
        );
    }
}
