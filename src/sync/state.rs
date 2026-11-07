//! Join phases, the pure transition machine, and the sync error taxonomy.
//!
//! Owner: W14 (E7); W17 reads this file but does not change it (53 §7).
//!
//! # Why a machine instead of a chain of `if`s
//!
//! The join sequence is a contract with the server (39 §2.4, 43 §8.1): a
//! snapshot that arrives during `ManifestFetch` must not be installed, and a
//! phase that is skipped must be visible as an error rather than as a state
//! that merely "looks odd". [`Machine::apply`] is a total function over
//! `(phase, event)`: legal pairs move, illegal pairs return
//! [`SyncError::IllegalTransition`]. There is no `_ => continue` arm.
//!
//! # Retry and resume
//!
//! `Failing` is the only phase that remembers where it came from. `Retry`
//! stores the current phase and moves to `Failing`; `Resume` returns to the
//! stored phase. This is the whole of 43 §8.1's "任意相位 → Failing → 回到
//! 失败前的相位" rule, and it is testable without I/O.

use std::fmt;

use crate::protocol::frame::Seq;
use crate::sync::ChunkId;

/// One join phase (43 §8.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SyncPhase {
    /// Before the welcome frame.
    Idle,
    /// `WELCOME` recorded; epoch and `current_seq` known.
    Handshake,
    /// Choosing the snapshot to pull.
    SnapshotSelect,
    /// Fetching snapshot parts.
    SnapshotPull,
    /// Digest verified; installing the state image.
    SnapshotInstall,
    /// Fetching the manifest and the blockmap index.
    ManifestFetch,
    /// Comparing manifests.
    DiffPlan,
    /// Rsync deltas for content-different files.
    RsyncRun,
    /// Whole-chunk fetches for remote-only files.
    ChunkFetch,
    /// Building the staging tree.
    StagingBuild,
    /// Flushing the staging tree.
    Durability,
    /// Renaming staged files into place.
    Apply,
    /// Writing the local manifest cache.
    Commit,
    /// Joined; live following begins.
    Online,
    /// Waiting to retry after a peer or transport failure.
    Failing,
    /// Terminal: kick, fatal error, or unmount.
    Aborted,
}

impl SyncPhase {
    /// Stable name for logs and `status`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Handshake => "handshake",
            Self::SnapshotSelect => "snapshot-select",
            Self::SnapshotPull => "snapshot-pull",
            Self::SnapshotInstall => "snapshot-install",
            Self::ManifestFetch => "manifest-fetch",
            Self::DiffPlan => "diff-plan",
            Self::RsyncRun => "rsync-run",
            Self::ChunkFetch => "chunk-fetch",
            Self::StagingBuild => "staging-build",
            Self::Durability => "durability",
            Self::Apply => "apply",
            Self::Commit => "commit",
            Self::Online => "online",
            Self::Failing => "failing",
            Self::Aborted => "aborted",
        }
    }

    /// Terminal phases accept no further join event.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Online | Self::Aborted)
    }

    /// True while the local tree is being brought to the cluster state.
    ///
    /// `status.sync.read_only` is exactly this predicate (43 §6.5).
    pub const fn is_joining(self) -> bool {
        !matches!(self, Self::Idle | Self::Online | Self::Aborted)
    }

    /// Every phase, in declaration order. Used by exhaustive tests.
    pub const ALL: [Self; 16] = [
        Self::Idle,
        Self::Handshake,
        Self::SnapshotSelect,
        Self::SnapshotPull,
        Self::SnapshotInstall,
        Self::ManifestFetch,
        Self::DiffPlan,
        Self::RsyncRun,
        Self::ChunkFetch,
        Self::StagingBuild,
        Self::Durability,
        Self::Apply,
        Self::Commit,
        Self::Online,
        Self::Failing,
        Self::Aborted,
    ];
}

/// One event the join driver can observe (43 §8.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SyncEvent {
    /// `WELCOME` accepted.
    Welcome,
    /// `WELCOME` carried a snapshot reference (or the request found one).
    SnapshotRef,
    /// No snapshot is available; the server must designate a generator.
    SnapshotAbsent,
    /// A snapshot was chosen.
    SnapshotSelected,
    /// Every part arrived and passed its per-part checks.
    PartsComplete,
    /// The state image is installed and `applied_seq = covered_seq`.
    Installed,
    /// Manifest and blockmap index decoded.
    ManifestDone,
    /// The diff plan exists.
    Planned,
    /// No file needs bytes; jump to staging.
    NoWork,
    /// Every rsync and chunk task finished.
    AllFilesDone,
    /// The staging tree is complete.
    Staged,
    /// `syncfs` returned.
    Durable,
    /// Every staged rename is applied.
    Applied,
    /// The local manifest cache is replaced.
    Committed,
    /// A retryable failure; remember the phase.
    Retry,
    /// Return from `Failing` to the remembered phase.
    Resume,
    /// A fatal condition; no further events are accepted.
    Abort,
}

impl SyncEvent {
    /// Stable name for logs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Welcome => "welcome",
            Self::SnapshotRef => "snapshot-ref",
            Self::SnapshotAbsent => "snapshot-absent",
            Self::SnapshotSelected => "snapshot-selected",
            Self::PartsComplete => "parts-complete",
            Self::Installed => "installed",
            Self::ManifestDone => "manifest-done",
            Self::Planned => "planned",
            Self::NoWork => "no-work",
            Self::AllFilesDone => "all-files-done",
            Self::Staged => "staged",
            Self::Durable => "durable",
            Self::Applied => "applied",
            Self::Committed => "committed",
            Self::Retry => "retry",
            Self::Resume => "resume",
            Self::Abort => "abort",
        }
    }

    /// Every event, in declaration order.
    pub const ALL: [Self; 17] = [
        Self::Welcome,
        Self::SnapshotRef,
        Self::SnapshotAbsent,
        Self::SnapshotSelected,
        Self::PartsComplete,
        Self::Installed,
        Self::ManifestDone,
        Self::Planned,
        Self::NoWork,
        Self::AllFilesDone,
        Self::Staged,
        Self::Durable,
        Self::Applied,
        Self::Committed,
        Self::Retry,
        Self::Resume,
        Self::Abort,
    ];
}

/// The stateless part of the transition table.
///
/// Returns `None` for every pair the table does not allow. `Retry`/`Resume`
/// are handled by [`Machine`] because they need the remembered phase.
pub fn transition(phase: SyncPhase, event: SyncEvent) -> Option<SyncPhase> {
    use SyncEvent as E;
    use SyncPhase as P;
    let next = match (phase, event) {
        (P::Idle, E::Welcome) => P::Handshake,
        (P::Handshake, E::SnapshotRef | E::SnapshotAbsent) => P::SnapshotSelect,
        (P::SnapshotSelect, E::SnapshotSelected) => P::SnapshotPull,
        (P::SnapshotPull, E::PartsComplete) => P::SnapshotInstall,
        (P::SnapshotInstall, E::Installed) => P::ManifestFetch,
        (P::ManifestFetch, E::ManifestDone) => P::DiffPlan,
        (P::DiffPlan, E::Planned) => P::RsyncRun,
        (P::DiffPlan | P::RsyncRun | P::ChunkFetch, E::NoWork | E::AllFilesDone) => P::StagingBuild,
        (P::StagingBuild, E::Staged) => P::Durability,
        (P::Durability, E::Durable) => P::Apply,
        (P::Apply, E::Applied) => P::Commit,
        (P::Commit, E::Committed) => P::Online,
        _ => return None,
    };
    Some(next)
}

/// The join phase machine.
#[derive(Clone, Debug)]
pub struct Machine {
    phase: SyncPhase,
    resume: Option<SyncPhase>,
}

impl Machine {
    /// A machine at `Idle`.
    pub const fn new() -> Self {
        Self {
            phase: SyncPhase::Idle,
            resume: None,
        }
    }

    /// The current phase.
    pub const fn phase(&self) -> SyncPhase {
        self.phase
    }

    /// The phase a `Resume` would return to.
    pub const fn resume_target(&self) -> Option<SyncPhase> {
        self.resume
    }

    /// Apply one event.
    ///
    /// # Errors
    ///
    /// [`SyncError::IllegalTransition`] when the table has no entry for the
    /// pair, or when `Resume` arrives outside `Failing`.
    pub fn apply(&mut self, event: SyncEvent) -> Result<SyncPhase, SyncError> {
        if self.phase == SyncPhase::Aborted {
            return match event {
                SyncEvent::Abort => Ok(SyncPhase::Aborted),
                _ => Err(SyncError::IllegalTransition {
                    from: self.phase,
                    event,
                }),
            };
        }
        match event {
            SyncEvent::Abort => {
                self.phase = SyncPhase::Aborted;
                self.resume = None;
                Ok(self.phase)
            }
            SyncEvent::Retry => {
                if self.phase != SyncPhase::Failing {
                    self.resume = Some(self.phase);
                }
                self.phase = SyncPhase::Failing;
                Ok(self.phase)
            }
            SyncEvent::Resume => match self.resume.take() {
                Some(target) if self.phase == SyncPhase::Failing => {
                    self.phase = target;
                    Ok(self.phase)
                }
                _ => Err(SyncError::IllegalTransition {
                    from: self.phase,
                    event,
                }),
            },
            other => {
                let next = transition(self.phase, other).ok_or(SyncError::IllegalTransition {
                    from: self.phase,
                    event: other,
                })?;
                self.phase = next;
                Ok(next)
            }
        }
    }
}

impl Default for Machine {
    fn default() -> Self {
        Self::new()
    }
}

/// How a failure may be handled (43 §8.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RetryClass {
    /// Retry the same source once, then switch.
    SamePeer,
    /// Switch peer; bounded by `PEER_RETRY`.
    OtherPeer,
    /// Join completes; the affected path returns `EIO`.
    Degrade,
    /// Abort the join.
    Fatal,
}

/// Everything the sync core can refuse.
///
/// Details are `&'static str` or `String` rather than `io::Error` so the value
/// is `Clone`-free, comparable in tests, and safe to log (paths never appear:
/// callers log `path_hash`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncError {
    /// A container failed to parse.
    Format(&'static str),
    /// A control payload would exceed its part budget.
    TooLarge {
        /// Which container.
        what: &'static str,
        /// Number of parts requested.
        parts: u32,
    },
    /// `covered_seq` in the container differs from the reference.
    CoveredSeqMismatch {
        /// Sequence named by the reference.
        expected: Seq,
        /// Sequence found in the container.
        found: Seq,
    },
    /// The state digest did not match the data parts.
    StateDigestMismatch,
    /// A part decoded to the wrong number of bytes.
    PartLengthMismatch {
        /// Part index.
        part: u32,
        /// Length the descriptor promised.
        expected: u32,
        /// Length actually assembled.
        found: u32,
    },
    /// A chunk was not obtainable from any source.
    ChunkUnavailable {
        /// Content identifier.
        id: ChunkId,
    },
    /// A chunk failed its authentication or its plaintext hash.
    ChunkCorrupt {
        /// Content identifier.
        id: ChunkId,
    },
    /// The event is not legal in the current phase.
    IllegalTransition {
        /// Current phase.
        from: SyncPhase,
        /// Rejected event.
        event: SyncEvent,
    },
    /// `WELCOME` named no snapshot and no generator was designated.
    SnapshotMissing,
    /// A bounded retry budget is spent.
    RetryExhausted {
        /// Which budget.
        what: &'static str,
    },
    /// Local I/O failed.
    Io(String),
    /// The control link failed.
    Link(String),
    /// The state provider refused or failed.
    State(String),
    /// The local tree scan failed.
    Local(String),
    /// The engine task is gone.
    EngineStopped,
    /// A join is already running.
    Busy,
}

impl SyncError {
    /// How the driver should react.
    pub const fn retry_class(&self) -> RetryClass {
        match self {
            Self::ChunkCorrupt { .. } => RetryClass::SamePeer,
            Self::ChunkUnavailable { .. }
            | Self::StateDigestMismatch
            | Self::CoveredSeqMismatch { .. }
            | Self::PartLengthMismatch { .. }
            | Self::SnapshotMissing
            | Self::Link(_) => RetryClass::OtherPeer,
            Self::RetryExhausted { .. } => RetryClass::Degrade,
            Self::Format(_)
            | Self::TooLarge { .. }
            | Self::IllegalTransition { .. }
            | Self::Io(_)
            | Self::State(_)
            | Self::Local(_)
            | Self::EngineStopped
            | Self::Busy => RetryClass::Fatal,
        }
    }

    /// True when the failure is worth another peer.
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self.retry_class(),
            RetryClass::SamePeer | RetryClass::OtherPeer
        )
    }
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(what) => write!(f, "malformed {what}"),
            Self::TooLarge { what, parts } => {
                write!(f, "{what} needs {parts} parts, over the control budget")
            }
            Self::CoveredSeqMismatch { expected, found } => write!(
                f,
                "covered_seq mismatch: reference {}, container {}",
                expected.get(),
                found.get()
            ),
            Self::StateDigestMismatch => f.write_str("state digest mismatch"),
            Self::PartLengthMismatch {
                part,
                expected,
                found,
            } => write!(
                f,
                "part {part} length {found}, descriptor promised {expected}"
            ),
            Self::ChunkUnavailable { id } => write!(f, "chunk {id} unavailable"),
            Self::ChunkCorrupt { id } => write!(f, "chunk {id} failed verification"),
            Self::IllegalTransition { from, event } => {
                write!(f, "event {} illegal in phase {}", event.name(), from.name())
            }
            Self::SnapshotMissing => f.write_str("no snapshot and no generator designated"),
            Self::RetryExhausted { what } => write!(f, "retry budget for {what} exhausted"),
            Self::Io(detail) => write!(f, "local I/O: {detail}"),
            Self::Link(detail) => write!(f, "control link: {detail}"),
            Self::State(detail) => write!(f, "state provider: {detail}"),
            Self::Local(detail) => write!(f, "local tree: {detail}"),
            Self::EngineStopped => f.write_str("sync engine stopped"),
            Self::Busy => f.write_str("a join is already running"),
        }
    }
}

impl std::error::Error for SyncError {}

impl From<std::io::Error> for SyncError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

impl From<crate::store::Errno> for SyncError {
    fn from(err: crate::store::Errno) -> Self {
        Self::Io(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 43 §8.1: the happy path visits every phase in order.
    #[test]
    fn u_state_happy_path() {
        let mut machine = Machine::new();
        let path = [
            SyncEvent::Welcome,
            SyncEvent::SnapshotRef,
            SyncEvent::SnapshotSelected,
            SyncEvent::PartsComplete,
            SyncEvent::Installed,
            SyncEvent::ManifestDone,
            SyncEvent::Planned,
            SyncEvent::AllFilesDone,
            SyncEvent::Staged,
            SyncEvent::Durable,
            SyncEvent::Applied,
            SyncEvent::Committed,
        ];
        let expected = [
            SyncPhase::Handshake,
            SyncPhase::SnapshotSelect,
            SyncPhase::SnapshotPull,
            SyncPhase::SnapshotInstall,
            SyncPhase::ManifestFetch,
            SyncPhase::DiffPlan,
            SyncPhase::RsyncRun,
            SyncPhase::StagingBuild,
            SyncPhase::Durability,
            SyncPhase::Apply,
            SyncPhase::Commit,
            SyncPhase::Online,
        ];
        for (event, phase) in path.into_iter().zip(expected) {
            assert_eq!(machine.apply(event), Ok(phase), "event {}", event.name());
        }
        assert!(machine.phase().is_terminal());
        assert!(!machine.phase().is_joining());
    }

    /// 43 §8.1: every phase can fail and resume to where it was.
    #[test]
    fn u_state_retry_returns_to_previous_phase() {
        for phase in SyncPhase::ALL {
            if phase.is_terminal() || phase == SyncPhase::Failing {
                continue;
            }
            let mut machine = Machine::new();
            machine.phase = phase;
            assert_eq!(machine.apply(SyncEvent::Retry), Ok(SyncPhase::Failing));
            assert_eq!(machine.resume_target(), Some(phase));
            assert_eq!(machine.apply(SyncEvent::Resume), Ok(phase));
            assert_eq!(machine.resume_target(), None);
        }
    }

    /// Illegal pairs are errors, never silent no-ops.
    #[test]
    fn u_state_illegal_transitions_are_errors() {
        assert_eq!(
            Machine::new().apply(SyncEvent::Committed),
            Err(SyncError::IllegalTransition {
                from: SyncPhase::Idle,
                event: SyncEvent::Committed,
            })
        );
        let mut failing = Machine::new();
        failing.phase = SyncPhase::Failing;
        assert_eq!(
            failing.apply(SyncEvent::Resume),
            Err(SyncError::IllegalTransition {
                from: SyncPhase::Failing,
                event: SyncEvent::Resume,
            })
        );
    }

    /// Abort is terminal and idempotent; every other event is refused.
    #[test]
    fn u_state_abort_is_terminal() {
        let mut machine = Machine::new();
        assert_eq!(machine.apply(SyncEvent::Abort), Ok(SyncPhase::Aborted));
        assert_eq!(machine.apply(SyncEvent::Abort), Ok(SyncPhase::Aborted));
        for event in SyncEvent::ALL {
            if event == SyncEvent::Abort {
                continue;
            }
            assert!(machine.apply(event).is_err(), "event {}", event.name());
        }
    }

    /// The table is total: every legal pair has exactly one destination and
    /// every terminal phase has none.
    #[test]
    fn u_state_table_is_total() {
        let mut legal = 0usize;
        for phase in SyncPhase::ALL {
            for event in SyncEvent::ALL {
                if let Some(next) = transition(phase, event) {
                    legal += 1;
                    assert_ne!(next, phase, "{} + {}", phase.name(), event.name());
                }
            }
        }
        assert_eq!(legal, 18);
        for phase in [SyncPhase::Online, SyncPhase::Aborted] {
            for event in SyncEvent::ALL {
                assert_eq!(transition(phase, event), None);
            }
        }
    }

    /// 43 §8.2: retry classes drive the peer switch budget.
    #[test]
    fn u_state_retry_classes() {
        assert_eq!(
            SyncError::ChunkCorrupt {
                id: crate::sync::ZERO_CHUNK,
            }
            .retry_class(),
            RetryClass::SamePeer
        );
        assert_eq!(
            SyncError::ChunkUnavailable {
                id: crate::sync::ZERO_CHUNK,
            }
            .retry_class(),
            RetryClass::OtherPeer
        );
        assert_eq!(
            SyncError::RetryExhausted { what: "chunk" }.retry_class(),
            RetryClass::Degrade
        );
        assert_eq!(
            SyncError::StateDigestMismatch.retry_class(),
            RetryClass::OtherPeer
        );
        assert_eq!(
            SyncError::Format("snapshot").retry_class(),
            RetryClass::Fatal
        );
        assert!(SyncError::StateDigestMismatch.is_retryable());
        assert!(!SyncError::Format("x").is_retryable());
    }
}
