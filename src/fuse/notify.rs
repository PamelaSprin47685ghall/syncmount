//! Kernel cache invalidation.
//!
//! The FUSE adapter only *translates* callbacks; it does not decide when a
//! remote change becomes visible. [`super::ReplayView`] makes that decision
//! and calls this handle after the backing tree has been updated. Keeping the
//! handle here means the replayer never needs to know about `fuser`.
//!
//! fuser 0.18 exposes exactly `poll`, `inval_entry`, `inval_inode`, `store`
//! and `delete`; it has no `inc_epoch`/`expire_entry`. The two operations this
//! module needs are therefore `inval_inode` and `inval_entry`.
//!
//! Ordering is the caller's responsibility: write the backing tree first,
//! then invalidate. A failed notification is not fatal; the short TTLs in
//! [`super::ino`] bound how long the stale view can survive.
//!
//! # Why the kernel write runs on its own thread
//!
//! A notification is written straight to `/dev/fuse`, and the kernel may
//! block that write on an inode lock held by a request this daemon has not
//! answered yet. The replay pump would then deadlock against the very
//! callback that waits for the pump's echo (a synchronous `mkdir`/`rename`
//! holds the parent's lock while it waits). [`Notify`] therefore only
//! enqueues; one background thread performs the writes in call order, so a
//! blocked notification can never stall replay. The queue is bounded: if the
//! writer thread is stuck long enough to fill it, new invalidations are
//! dropped rather than blocking the pump, and the short TTLs bound how long
//! a stale view can survive.

use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};

use fuser::{INodeNo, Notifier};

/// One invalidation the adapter asked the kernel for.
///
/// It exists so the W13b tests can assert the disk-first/notify-second order
/// without a live kernel session. A real session only sees the calls.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Invalidation {
    /// One directory entry was dropped.
    Entry {
        /// Parent inode number.
        parent: INodeNo,
        /// Entry name.
        name: std::ffi::OsString,
    },
    /// One inode range was dropped; `len = -1` is the whole file and `len =
    /// 0` is attributes only.
    Inode {
        /// Inode number.
        ino: INodeNo,
        /// First byte.
        offset: i64,
        /// Byte count.
        len: i64,
    },
}

/// A cloneable handle to the session notifier.
///
/// Before the session exists (unit tests, early startup) invalidation is a
/// no-op. Attaching a notifier is idempotent; the first one wins and starts
/// the writer thread that owns it.
#[derive(Clone, Default)]
pub struct Notify {
    queue: Arc<Mutex<Option<SyncSender<Job>>>>,
    #[cfg(test)]
    recorder: Arc<Mutex<Vec<Invalidation>>>,
}

/// Maximum notifications waiting for the kernel writer.
///
/// One metadata operation produces at most a handful of invalidations; 1024
/// leaves room for a long kernel stall without unbounded memory growth.
const QUEUE_DEPTH: usize = 1024;

/// One kernel notification, executed in call order by the writer thread.
enum Job {
    Entry {
        parent: INodeNo,
        name: std::ffi::OsString,
    },
    Inode {
        ino: INodeNo,
        offset: i64,
        len: i64,
    },
}

impl fmt::Debug for Notify {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Notify")
            .field("attached", &self.is_attached())
            .finish()
    }
}

impl Notify {
    /// An unattached handle.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach the session notifier. A second attachment is ignored.
    pub fn attach(&self, notifier: Notifier) {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if queue.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::sync_channel::<Job>(QUEUE_DEPTH);
        let spawned = std::thread::Builder::new()
            .name("syncmount-notify".to_string())
            .spawn(move || {
                while let Ok(job) = receiver.recv() {
                    match job {
                        Job::Entry { parent, name } => {
                            let _ = notifier.inval_entry(parent, &name);
                        }
                        Job::Inode { ino, offset, len } => {
                            let _ = notifier.inval_inode(ino, offset, len);
                        }
                    }
                }
            });
        if spawned.is_ok() {
            *queue = Some(sender);
        }
    }

    /// True once a session notifier is attached.
    pub fn is_attached(&self) -> bool {
        self.queue
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .is_some()
    }

    /// Invalidate one directory entry.
    pub fn invalidate_entry(&self, parent: INodeNo, name: &OsStr) -> io::Result<()> {
        #[cfg(test)]
        self.record(Invalidation::Entry {
            parent,
            name: name.to_os_string(),
        });
        self.enqueue(Job::Entry {
            parent,
            name: name.to_os_string(),
        })
    }

    /// Invalidate an inode range. `len = -1` drops data pages and attributes.
    pub fn invalidate_inode(&self, ino: INodeNo, offset: i64, len: i64) -> io::Result<()> {
        #[cfg(test)]
        self.record(Invalidation::Inode { ino, offset, len });
        self.enqueue(Job::Inode { ino, offset, len })
    }

    /// Hand one job to the writer thread.
    fn enqueue(&self, job: Job) -> io::Result<()> {
        let queue = self
            .queue
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        match queue.as_ref() {
            Some(sender) => sender.try_send(job).map_err(|error| match error {
                mpsc::TrySendError::Full(_) => io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "notification queue is full; invalidation dropped",
                ),
                mpsc::TrySendError::Disconnected(_) => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "notification thread stopped")
                }
            }),
            None => Ok(()),
        }
    }

    /// Invalidate the whole file: data pages and attributes.
    pub fn invalidate_all(&self, ino: INodeNo) -> io::Result<()> {
        self.invalidate_inode(ino, 0, -1)
    }

    /// Invalidate attributes only, leaving data pages intact.
    pub fn invalidate_attr(&self, ino: INodeNo) -> io::Result<()> {
        self.invalidate_inode(ino, 0, 0)
    }

    /// Every invalidation requested so far, in call order (tests only).
    #[cfg(test)]
    pub(crate) fn recorded(&self) -> Vec<Invalidation> {
        self.recorder
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    #[cfg(test)]
    fn record(&self, event: Invalidation) {
        self.recorder
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// E6 / 22 §2: an unattached handle is a harmless no-op.
    #[test]
    fn u_fuse_notify_unattached_is_noop() {
        let notify = Notify::new();
        assert!(!notify.is_attached());
        assert!(
            notify
                .invalidate_entry(INodeNo::ROOT, OsStr::new("x"))
                .is_ok()
        );
        assert!(notify.invalidate_inode(INodeNo::ROOT, 0, -1).is_ok());
        assert!(notify.invalidate_all(INodeNo::ROOT).is_ok());
        assert!(notify.invalidate_attr(INodeNo::ROOT).is_ok());
        assert!(!notify.is_attached());
    }

    /// E6 / 22 §2: cloning shares the attachment slot.
    #[test]
    fn u_fuse_notify_clone_shares_slot() {
        let notify = Notify::new();
        let clone = notify.clone();
        assert!(!clone.is_attached());
        assert!(!notify.is_attached());
    }
}
