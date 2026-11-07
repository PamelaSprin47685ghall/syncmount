//! Client lifecycle: a pure state machine and the write gate it drives.
//!
//! Owner: W12 (E5). See 41 §6, 51 §5.1, 45 INV-17/21 and 53 W12.
//!
//! [`Lifecycle`] holds no handle and performs no I/O. [`Lifecycle::on`] maps
//! one [`Event`] to a list of [`Action`]s; the driver in [`crate::client`]
//! executes those actions and feeds the result back as another event. That
//! split is what makes the state machine exhaustively testable and what keeps
//! a failed syscall from leaving the machine half-way through a transition.
//!
//! ```text
//! BOOT -> LOCKED -> CLEANUP -> MOUNTING -> JOINING -> STEADY
//!                                    |          |
//!                                    +----------+-----> UNMOUNTING
//!                                                         |     |
//!                                                       EXIT   DEGRADED_RO
//! ```
//!
//! Exit codes are fixed by 41 §6.3 / 45 INV-17:
//!
//! | code | meaning |
//! |---|---|
//! | 0 | normal unmount after SIGINT/SIGTERM/SIGHUP |
//! | 1 | bad arguments, already running, second SIGTERM |
//! | 2 | startup failure (stale mount, lock, FUSE mount, initial JOIN) |
//! | 3 | reserved for a corrupt audit journal |
//! | 10 | disconnect, KICK or a fatal replay/transport condition |
//!
//! A failed unmount is **not** exit 2: the machine enters
//! [`State::DegradedReadOnly`] and stays resident with writes returning
//! `EROFS`, because a dead mountpoint is worse than a read-only one.

use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use crate::protocol::KickReason;
use crate::store::Errno;

/// Normal unmount.
pub const EXIT_OK: i32 = 0;
/// Argument, environment or single-instance failure.
pub const EXIT_USAGE: i32 = 1;
/// Startup failure: stale mount, lock, mount or the initial JOIN.
pub const EXIT_STARTUP: i32 = 2;
/// Reserved for a corrupt audit journal (41 §6.3).
pub const EXIT_AUDIT: i32 = 3;
/// Disconnect or KICK.
pub const EXIT_DISCONNECTED: i32 = 10;

/// Every exit code the machine may emit.
pub const EXIT_CODES: [i32; 5] = [
    EXIT_OK,
    EXIT_USAGE,
    EXIT_STARTUP,
    EXIT_AUDIT,
    EXIT_DISCONNECTED,
];

/// Quiesce budget before unmount (41 §6.2).
pub const QUIESCE_BUDGET: Duration = Duration::from_millis(1_200);
/// Flush budget before unmount (41 §6.2).
pub const FLUSH_BUDGET: Duration = Duration::from_millis(500);

/// One lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum State {
    /// Configuration is being validated.
    Boot = 0,
    /// The single-instance lock is being acquired.
    Locked = 1,
    /// Stale mounts and staging residue are being removed.
    Cleanup = 2,
    /// FUSE is being mounted and the backing root opened.
    Mounting = 3,
    /// The JOIN handshake and manifest install are running; writes are EROFS.
    Joining = 4,
    /// The mount is fully online.
    Steady = 5,
    /// Quiesce, flush and unmount are running; writes are ENOTCONN.
    Unmounting = 6,
    /// Every unmount attempt failed; reads continue, writes are EROFS.
    DegradedReadOnly = 7,
    /// The process is about to exit; the state is terminal.
    Exited = 8,
}

impl State {
    /// Every state, in declaration order.
    pub const ALL: [Self; 9] = [
        Self::Boot,
        Self::Locked,
        Self::Cleanup,
        Self::Mounting,
        Self::Joining,
        Self::Steady,
        Self::Unmounting,
        Self::DegradedReadOnly,
        Self::Exited,
    ];

    /// Stable upper-case name for logs and the status document.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Boot => "BOOT",
            Self::Locked => "LOCKED",
            Self::Cleanup => "CLEANUP",
            Self::Mounting => "MOUNTING",
            Self::Joining => "JOINING",
            Self::Steady => "STEADY",
            Self::Unmounting => "UNMOUNTING",
            Self::DegradedReadOnly => "DEGRADED_RO",
            Self::Exited => "EXITED",
        }
    }

    /// Whether a mutation is allowed in this state.
    ///
    /// JOINING and DEGRADED_RO refuse with `EROFS`; UNMOUNTING and every
    /// pre-mount state refuse with `ENOTCONN` (41 invariant 11).
    pub const fn write_errno(self) -> Result<(), Errno> {
        match self {
            Self::Steady => Ok(()),
            Self::Joining | Self::DegradedReadOnly => Err(Errno::EROFS),
            Self::Boot
            | Self::Locked
            | Self::Cleanup
            | Self::Mounting
            | Self::Unmounting
            | Self::Exited => Err(Errno(libc::ENOTCONN)),
        }
    }

    /// Decode the atomic representation used by [`WriteGate`].
    const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Boot),
            1 => Some(Self::Locked),
            2 => Some(Self::Cleanup),
            3 => Some(Self::Mounting),
            4 => Some(Self::Joining),
            5 => Some(Self::Steady),
            6 => Some(Self::Unmounting),
            7 => Some(Self::DegradedReadOnly),
            8 => Some(Self::Exited),
            _ => None,
        }
    }
}

/// The write gate shared by the FUSE callbacks and the lifecycle driver.
///
/// It is a lock-free mirror of [`Lifecycle::state`]. The driver updates it
/// after every transition; FUSE callbacks only read it, so a state change
/// takes effect before any queued action runs.
#[derive(Debug)]
pub struct WriteGate {
    state: AtomicU8,
}

impl WriteGate {
    /// Build a gate in `state`.
    pub fn new(state: State) -> Self {
        Self {
            state: AtomicU8::new(state as u8),
        }
    }

    /// Current state.
    pub fn state(&self) -> State {
        State::from_u8(self.state.load(Ordering::Acquire)).unwrap_or(State::Exited)
    }

    /// Publish a new state.
    pub fn set(&self, state: State) {
        self.state.store(state as u8, Ordering::Release);
    }

    /// Refuse a mutation when the gate is closed.
    pub fn check(&self) -> Result<(), Errno> {
        self.state().write_errno()
    }

    /// Explicit alias for write-path call sites.
    pub fn check_write(&self) -> Result<(), Errno> {
        self.check()
    }

    /// Whether mutations are currently allowed.
    pub fn is_open(&self) -> bool {
        self.check().is_ok()
    }
}

impl Default for WriteGate {
    fn default() -> Self {
        Self::new(State::Boot)
    }
}

/// Why the transport ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// Clean end of stream.
    Eof,
    /// `RST` or a socket error.
    Reset,
    /// A write to the uplink failed.
    WriteError,
    /// The server sent an `ERROR` frame.
    Server,
    /// The transport failed in a way the caller could not classify.
    Transport,
    /// An internal task ended unexpectedly.
    Internal,
}

/// Signal that asks for an orderly stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sig {
    /// `SIGINT`.
    Int,
    /// `SIGTERM`.
    Term,
    /// `SIGHUP`.
    Hup,
    /// `SIGQUIT` (no orderly unmount).
    Quit,
    /// `SIGABRT` (no orderly unmount).
    Abrt,
}

/// A failure before the mount exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupError {
    /// The configuration is invalid.
    Config,
}

/// Failure to acquire the single-instance lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockError {
    /// Another process owns the mount.
    Busy,
    /// The lock file could not be opened or locked.
    Io,
}

/// Failure to remove stale state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupError {
    /// A stale mount could not be detached.
    StaleMount,
    /// The staging directory could not be removed.
    Staging,
}

/// Failure to mount FUSE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountError {
    /// The backing root could not be opened.
    Root,
    /// `mount(2)` failed.
    Fuse,
}

/// Failure of the JOIN handshake or manifest install.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinError {
    /// The transport could not be dialled.
    Transport,
    /// HELLO/WELCOME failed.
    Handshake,
    /// The manifest or snapshot install failed.
    Sync,
    /// The server rejected the session.
    Rejected,
}

/// Failure of the unmount sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnmountError {
    /// `fusermount3 -u`, `-uz` and `MNT_DETACH` all failed.
    Exhausted,
    /// The session thread panicked.
    Panic,
}

/// Why the replay engine asked for a rebuild.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResyncReason {
    /// The server restarted with a new epoch.
    EpochChanged,
    /// A sequence was reused by an unseen operation.
    Rollback,
    /// A hole did not fill.
    SeqGap,
}

/// A condition that ends the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatalError {
    /// The replay state cannot be rebuilt.
    Replay,
    /// A disk effect failed after the order fixed it.
    Materialize,
    /// A frame violated a protocol invariant.
    Protocol,
    /// A local operation was echoed after a later one; the uplink lost a frame.
    UplinkLost,
    /// The oldest unacknowledged operation exceeded the stall threshold.
    UplinkStall,
    /// Three rebuilds without a steady window.
    ResyncLoop,
    /// A task panicked or an invariant broke locally.
    Internal,
}

/// The result of a successful JOIN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JoinOutcome {
    /// Server epoch that was installed.
    pub epoch: u64,
    /// Watermark of the installed view, i.e. the replayer's starting point.
    ///
    /// It is [`crate::client::JoinReport::view_seq`], never the server's
    /// `current_seq` guessed by the driver.
    pub covered: u64,
}

/// Retry schedule for a JOIN whose `WELCOME` has no remote view yet.
///
/// The schedule is deliberately small and bounded: 1, 2, 4, 8 and 16
/// seconds, five retries in total. A client that still sees no view after
/// them refuses the JOIN instead of building an empty view, because
/// cluster-wins over an empty view deletes every local-only path.
///
/// The policy is pure. [`JoinRetryPolicy::next_delay`] only advances an
/// index; the driver owns the sleep, so tests exercise the schedule without
/// waiting on a clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JoinRetryPolicy {
    delays: [Duration; JOIN_RETRY_LIMIT],
    used: u32,
}

/// Number of retries a JOIN may spend waiting for a view.
pub const JOIN_RETRY_LIMIT: usize = 5;

impl JoinRetryPolicy {
    /// 1, 2, 4, 8 and 16 seconds.
    pub const DELAYS: [Duration; JOIN_RETRY_LIMIT] = [
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(4),
        Duration::from_secs(8),
        Duration::from_secs(16),
    ];

    /// A fresh schedule with no retry spent.
    pub const fn new() -> Self {
        Self {
            delays: Self::DELAYS,
            used: 0,
        }
    }

    /// Next delay, or `None` when the retry budget is exhausted.
    pub fn next_delay(&mut self) -> Option<Duration> {
        let delay = self.delays.get(self.used as usize).copied()?;
        self.used += 1;
        Some(delay)
    }

    /// Retries spent so far.
    pub const fn retries_used(&self) -> u32 {
        self.used
    }

    /// Total retries this policy allows.
    pub const fn max_retries(&self) -> u32 {
        JOIN_RETRY_LIMIT as u32
    }

    /// Start a new JOIN at the first delay.
    pub fn reset(&mut self) {
        self.used = 0;
    }
}

impl Default for JoinRetryPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// One input to the lifecycle machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// Configuration validation finished.
    Prepared(Result<(), SetupError>),
    /// The single-instance lock attempt finished.
    LockAcquired(Result<(), LockError>),
    /// Stale-mount and staging cleanup finished.
    Cleaned(Result<(), CleanupError>),
    /// FUSE mount finished.
    FuseMounted(Result<(), MountError>),
    /// JOIN finished.
    Joined(Result<JoinOutcome, JoinError>),
    /// The transport ended.
    Disconnected(Cause),
    /// The server sent a KICK.
    Kick(KickReason),
    /// The server epoch changed.
    EpochChanged(u64),
    /// The replay engine requires a rebuild.
    Resync(ResyncReason),
    /// A fatal local or replay condition.
    Fatal(FatalError),
    /// A signal was delivered.
    Signal(Sig),
    /// The flush budget expired and local data is durable.
    FlushDone,
    /// One unmount attempt finished.
    UnmountTried(Result<(), UnmountError>),
    /// The resync budget was exhausted.
    BudgetExpired,
}

/// One effect the driver must perform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Remove stale mounts and staging residue.
    CleanupStale,
    /// Acquire the single-instance lock.
    AcquireLock,
    /// Append the audit record for this start.
    AuditJournal,
    /// Mount FUSE and open the backing root.
    MountFuse,
    /// Dial, HELLO/WELCOME, install the snapshot and start following.
    StartJoin,
    /// Publish [`State::Steady`] to the write gate.
    OpenWriteGate,
    /// Publish a closed gate.
    CloseWriteGate,
    /// Wait for in-flight callbacks to drain.
    Quiesce(Duration),
    /// Flush local data; then emit [`Event::FlushDone`].
    Flush(Duration),
    /// Run the three-step unmount.
    Unmount,
    /// Keep the mount resident and serve reads only.
    DegradeReadOnly,
    /// Release the single-instance lock.
    ReleaseLock,
    /// Terminate with this code.
    Exit(i32),
}

/// Why the machine is where it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// Configuration validation failed.
    Setup,
    /// The single-instance lock failed.
    Lock,
    /// Stale-state cleanup failed.
    Cleanup,
    /// FUSE mount failed.
    Mount,
    /// The initial JOIN failed.
    Join,
    /// The transport ended.
    Disconnected,
    /// The server sent a KICK.
    Kick,
    /// A replay or materialisation failure.
    Fatal,
    /// A signal asked for an orderly stop.
    Signal,
    /// The resync budget was exhausted.
    ResyncLoop,
}

/// The pure lifecycle machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lifecycle {
    state: State,
    exit: i32,
    reason: Option<Reason>,
    steady_seen: bool,
}

impl Lifecycle {
    /// Start in [`State::Boot`].
    pub const fn new() -> Self {
        Self {
            state: State::Boot,
            exit: EXIT_OK,
            reason: None,
            steady_seen: false,
        }
    }

    /// Current state.
    pub const fn state(&self) -> State {
        self.state
    }

    /// Exit code selected by the last transition.
    pub const fn exit_code(&self) -> i32 {
        self.exit
    }

    /// Why the machine entered its current state, when known.
    pub const fn reason(&self) -> Option<Reason> {
        self.reason
    }

    /// Whether the mount has ever reached STEADY.
    pub const fn steady_seen(&self) -> bool {
        self.steady_seen
    }

    /// Apply one event. Pure: no I/O, no clock, no randomness.
    pub fn on(&mut self, event: Event) -> Vec<Action> {
        use Action::{
            AcquireLock, AuditJournal, CleanupStale, CloseWriteGate, DegradeReadOnly, MountFuse,
            OpenWriteGate, ReleaseLock, StartJoin, Unmount,
        };
        use Event::{
            BudgetExpired, Cleaned, Disconnected, EpochChanged, Fatal, FlushDone, FuseMounted,
            Joined, Kick, LockAcquired, Prepared, Resync, Signal, UnmountTried,
        };
        use State::{
            Boot, Cleanup, DegradedReadOnly, Exited, Joining, Locked, Mounting, Steady, Unmounting,
        };

        match (self.state, event) {
            // --- BOOT -----------------------------------------------------
            (Boot, Prepared(Ok(()))) => self.enter(Locked, Reason::Setup, vec![AcquireLock]),
            (Boot, Prepared(Err(_))) => self.finish(EXIT_USAGE, Reason::Setup, Vec::new()),

            // --- LOCKED ---------------------------------------------------
            (Locked, LockAcquired(Ok(()))) => self.enter(Cleanup, Reason::Lock, vec![CleanupStale]),
            (Locked, LockAcquired(Err(_))) => self.finish(EXIT_USAGE, Reason::Lock, Vec::new()),

            // --- CLEANUP --------------------------------------------------
            (Cleanup, Cleaned(Ok(()))) => {
                self.enter(Mounting, Reason::Cleanup, vec![AuditJournal, MountFuse])
            }
            (Cleanup, Cleaned(Err(_))) => {
                self.finish(EXIT_STARTUP, Reason::Cleanup, vec![ReleaseLock])
            }

            // --- MOUNTING -------------------------------------------------
            (Mounting, FuseMounted(Ok(()))) => {
                self.enter(Joining, Reason::Mount, vec![CloseWriteGate, StartJoin])
            }
            (Mounting, FuseMounted(Err(_))) => {
                self.finish(EXIT_STARTUP, Reason::Mount, vec![ReleaseLock])
            }
            (Mounting, Disconnected(_) | Kick(_) | Fatal(_)) => {
                self.unmount(EXIT_DISCONNECTED, Reason::Disconnected)
            }
            (Mounting, Signal(_)) => self.unmount(EXIT_OK, Reason::Signal),

            // --- JOINING --------------------------------------------------
            (Joining, Joined(Ok(_))) => {
                self.steady_seen = true;
                self.enter(Steady, Reason::Join, vec![OpenWriteGate])
            }
            (Joining, Joined(Err(_))) => {
                let code = if self.steady_seen {
                    EXIT_DISCONNECTED
                } else {
                    EXIT_STARTUP
                };
                self.unmount(code, Reason::Join)
            }
            (Joining, Disconnected(_) | Kick(_) | Fatal(_) | BudgetExpired) => {
                self.unmount(EXIT_DISCONNECTED, Reason::Disconnected)
            }
            (Joining, Signal(_)) => self.unmount(EXIT_OK, Reason::Signal),

            // --- STEADY ---------------------------------------------------
            (Steady, Disconnected(_) | Kick(_) | Fatal(_) | BudgetExpired) => {
                self.unmount(EXIT_DISCONNECTED, Reason::Disconnected)
            }
            (Steady, Signal(_)) => self.unmount(EXIT_OK, Reason::Signal),
            (Steady, EpochChanged(_) | Resync(_)) => {
                self.enter(Joining, Reason::Fatal, vec![CloseWriteGate, StartJoin])
            }

            // --- UNMOUNTING ----------------------------------------------
            (Unmounting, FlushDone) => vec![Unmount],
            (Unmounting, UnmountTried(Ok(()))) => {
                let code = self.exit;
                self.finish(
                    code,
                    self.reason.unwrap_or(Reason::Signal),
                    vec![ReleaseLock],
                )
            }
            (Unmounting, UnmountTried(Err(_))) => {
                self.enter(DegradedReadOnly, Reason::Fatal, vec![DegradeReadOnly])
            }
            (Unmounting, Signal(_)) => {
                // A second TERM cannot wait for a clean drain.
                self.finish(EXIT_USAGE, Reason::Signal, vec![Unmount, ReleaseLock])
            }

            // --- DEGRADED_RO ---------------------------------------------
            (DegradedReadOnly, Signal(_)) => {
                self.state = Unmounting;
                self.exit = EXIT_OK;
                self.reason = Some(Reason::Signal);
                vec![CloseWriteGate, Unmount]
            }

            // --- EXITED and every unexpected pair ------------------------
            (Exited, _) => Vec::new(),
            _ => Vec::new(),
        }
    }

    fn enter(&mut self, state: State, reason: Reason, actions: Vec<Action>) -> Vec<Action> {
        self.state = state;
        self.reason = Some(reason);
        actions
    }

    fn finish(&mut self, code: i32, reason: Reason, mut actions: Vec<Action>) -> Vec<Action> {
        self.state = State::Exited;
        self.exit = code;
        self.reason = Some(reason);
        actions.push(Action::Exit(code));
        actions
    }

    fn unmount(&mut self, code: i32, reason: Reason) -> Vec<Action> {
        self.state = State::Unmounting;
        self.exit = code;
        self.reason = Some(reason);
        vec![
            Action::CloseWriteGate,
            Action::Quiesce(QUIESCE_BUDGET),
            Action::Flush(FLUSH_BUDGET),
        ]
    }
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// The backoff is exactly 1/2/4/8/16 s and stops after five retries.
    #[test]
    fn u_join_retry_policy_backs_off_and_stops() {
        let mut policy = JoinRetryPolicy::new();
        let delays: Vec<_> = std::iter::from_fn(|| policy.next_delay()).collect();
        assert_eq!(
            delays,
            [1u64, 2, 4, 8, 16].map(Duration::from_secs).to_vec(),
            "JOIN retry delays"
        );
        assert_eq!(policy.retries_used(), policy.max_retries());
        assert_eq!(policy.next_delay(), None, "the retry budget is bounded");

        policy.reset();
        assert_eq!(policy.retries_used(), 0);
        assert_eq!(policy.next_delay(), Some(Duration::from_secs(1)));
    }

    fn sample_events() -> Vec<Event> {
        vec![
            Event::Prepared(Ok(())),
            Event::LockAcquired(Ok(())),
            Event::Cleaned(Ok(())),
            Event::FuseMounted(Ok(())),
            Event::Joined(Ok(JoinOutcome {
                epoch: 7,
                covered: 42,
            })),
            Event::Disconnected(Cause::Eof),
            Event::Kick(KickReason::HeartbeatTimeout),
            Event::EpochChanged(8),
            Event::Resync(ResyncReason::SeqGap),
            Event::Fatal(FatalError::Protocol),
            Event::Signal(Sig::Term),
            Event::FlushDone,
            Event::UnmountTried(Ok(())),
            Event::BudgetExpired,
        ]
    }

    fn drive_to_steady(lifecycle: &mut Lifecycle) -> Vec<Action> {
        let mut actions = Vec::new();
        actions.extend(lifecycle.on(Event::Prepared(Ok(()))));
        actions.extend(lifecycle.on(Event::LockAcquired(Ok(()))));
        actions.extend(lifecycle.on(Event::Cleaned(Ok(()))));
        actions.extend(lifecycle.on(Event::FuseMounted(Ok(()))));
        actions.extend(lifecycle.on(Event::Joined(Ok(JoinOutcome {
            epoch: 1,
            covered: 0,
        }))));
        actions
    }

    fn drive(gate: &WriteGate, lifecycle: &mut Lifecycle, event: Event) -> Vec<Action> {
        let actions = lifecycle.on(event);
        gate.set(lifecycle.state());
        actions
    }

    /// 53 W12: every event in every state is total, deterministic and emits
    /// only legal actions. The state graph below is the exhaustive table.
    #[test]
    fn u_lifecycle_all_events_all_states() {
        let events = sample_events();
        assert_eq!(events.len(), 14);

        for state in State::ALL {
            for event in &events {
                let mut lifecycle = Lifecycle::new();
                lifecycle.state = state;
                let actions = lifecycle.on(*event);
                let to = lifecycle.state;

                assert!(
                    State::ALL.contains(&to),
                    "{state:?} + {event:?} produced an unknown state"
                );
                assert!(
                    actions
                        .iter()
                        .filter(|a| matches!(a, Action::Exit(_)))
                        .count()
                        <= 1,
                    "{state:?} + {event:?} emitted more than one exit"
                );
                for action in &actions {
                    if let Action::Exit(code) = action {
                        assert!(
                            EXIT_CODES.contains(code),
                            "{state:?} + {event:?} emitted an unknown exit code {code}"
                        );
                    }
                }

                if state == State::Exited {
                    assert_eq!(to, State::Exited, "EXITED must be terminal");
                    assert!(actions.is_empty(), "EXITED must emit no action");
                }

                let legal = match state {
                    State::Boot => matches!(event, Event::Prepared(_)),
                    State::Locked => matches!(event, Event::LockAcquired(_)),
                    State::Cleanup => matches!(event, Event::Cleaned(_)),
                    State::Mounting => matches!(
                        event,
                        Event::FuseMounted(_)
                            | Event::Disconnected(_)
                            | Event::Kick(_)
                            | Event::Fatal(_)
                            | Event::Signal(_)
                    ),
                    State::Joining => matches!(
                        event,
                        Event::Joined(_)
                            | Event::Disconnected(_)
                            | Event::Kick(_)
                            | Event::Fatal(_)
                            | Event::BudgetExpired
                            | Event::Signal(_)
                    ),
                    State::Steady => matches!(
                        event,
                        Event::Disconnected(_)
                            | Event::Kick(_)
                            | Event::Fatal(_)
                            | Event::BudgetExpired
                            | Event::Signal(_)
                            | Event::EpochChanged(_)
                            | Event::Resync(_)
                    ),
                    State::Unmounting => matches!(
                        event,
                        Event::FlushDone | Event::UnmountTried(_) | Event::Signal(_)
                    ),
                    State::DegradedReadOnly => matches!(event, Event::Signal(_)),
                    State::Exited => false,
                };

                if legal {
                    assert!(
                        !actions.is_empty(),
                        "{state:?} + {event:?} should emit an action"
                    );
                } else {
                    assert_eq!(to, state, "{state:?} + {event:?} should be ignored");
                    assert!(
                        actions.is_empty(),
                        "{state:?} + {event:?} should emit no action"
                    );
                }

                // The gate is a mirror of the state and never disagrees.
                let gate = WriteGate::new(to);
                assert_eq!(gate.check(), to.write_errno());
                assert_eq!(gate.state(), to);
            }
        }
    }

    /// 41 §6.1: the happy path opens the gate only at STEADY.
    #[test]
    fn u_lifecycle_happy_path() {
        let mut lifecycle = Lifecycle::new();
        let actions = drive_to_steady(&mut lifecycle);

        assert_eq!(lifecycle.state(), State::Steady);
        assert_eq!(lifecycle.exit_code(), EXIT_OK);
        assert!(lifecycle.steady_seen());
        assert!(actions.contains(&Action::AcquireLock));
        assert!(actions.contains(&Action::CleanupStale));
        assert!(actions.contains(&Action::MountFuse));
        assert!(actions.contains(&Action::StartJoin));
        assert!(actions.contains(&Action::OpenWriteGate));
        assert!(!actions.iter().any(|a| matches!(a, Action::Exit(_))));
    }

    /// 45 F-EXIT / INV-17: every terminal path uses the fixed code.
    #[test]
    fn u_lifecycle_f_exit_codes() {
        let mut lifecycle = Lifecycle::new();
        assert_eq!(
            lifecycle.on(Event::Prepared(Err(SetupError::Config))),
            vec![Action::Exit(EXIT_USAGE)]
        );
        assert_eq!(lifecycle.exit_code(), EXIT_USAGE);

        let mut lifecycle = Lifecycle::new();
        lifecycle.on(Event::Prepared(Ok(())));
        assert_eq!(
            lifecycle.on(Event::LockAcquired(Err(LockError::Busy))),
            vec![Action::Exit(EXIT_USAGE)]
        );

        let mut lifecycle = Lifecycle::new();
        lifecycle.on(Event::Prepared(Ok(())));
        lifecycle.on(Event::LockAcquired(Ok(())));
        let actions = lifecycle.on(Event::Cleaned(Err(CleanupError::StaleMount)));
        assert_eq!(
            actions,
            vec![Action::ReleaseLock, Action::Exit(EXIT_STARTUP)]
        );

        let mut lifecycle = Lifecycle::new();
        lifecycle.on(Event::Prepared(Ok(())));
        lifecycle.on(Event::LockAcquired(Ok(())));
        lifecycle.on(Event::Cleaned(Ok(())));
        let actions = lifecycle.on(Event::FuseMounted(Err(MountError::Fuse)));
        assert_eq!(
            actions,
            vec![Action::ReleaseLock, Action::Exit(EXIT_STARTUP)]
        );

        // Initial JOIN failure is a startup failure, not a disconnect.
        let mut lifecycle = Lifecycle::new();
        lifecycle.on(Event::Prepared(Ok(())));
        lifecycle.on(Event::LockAcquired(Ok(())));
        lifecycle.on(Event::Cleaned(Ok(())));
        lifecycle.on(Event::FuseMounted(Ok(())));
        let actions = lifecycle.on(Event::Joined(Err(JoinError::Sync)));
        assert_eq!(lifecycle.state(), State::Unmounting);
        assert_eq!(lifecycle.exit_code(), EXIT_STARTUP);
        assert!(actions.contains(&Action::CloseWriteGate));
        let actions = lifecycle.on(Event::UnmountTried(Ok(())));
        assert_eq!(
            actions,
            vec![Action::ReleaseLock, Action::Exit(EXIT_STARTUP)]
        );
    }

    /// 45 I-DISC / 31:M2-8: a disconnect closes the gate, unmounts and exits
    /// 10; a fresh process then remounts and reaches STEADY again.
    #[test]
    fn u_lifecycle_i_disconnect_unmount_and_remount() {
        let gate = WriteGate::new(State::Boot);
        let mut lifecycle = Lifecycle::new();
        drive_to_steady(&mut lifecycle);
        gate.set(lifecycle.state());
        assert_eq!(gate.check(), Ok(()));

        let actions = drive(&gate, &mut lifecycle, Event::Disconnected(Cause::Eof));
        assert_eq!(lifecycle.state(), State::Unmounting);
        assert_eq!(lifecycle.exit_code(), EXIT_DISCONNECTED);
        assert_eq!(gate.check(), Err(Errno(libc::ENOTCONN)));
        assert_eq!(
            actions,
            vec![
                Action::CloseWriteGate,
                Action::Quiesce(QUIESCE_BUDGET),
                Action::Flush(FLUSH_BUDGET),
            ]
        );

        assert_eq!(
            drive(&gate, &mut lifecycle, Event::FlushDone),
            vec![Action::Unmount]
        );
        let actions = drive(&gate, &mut lifecycle, Event::UnmountTried(Ok(())));
        assert_eq!(lifecycle.state(), State::Exited);
        assert_eq!(
            actions,
            vec![Action::ReleaseLock, Action::Exit(EXIT_DISCONNECTED)]
        );

        // Remount: no state survives the process exit.
        let gate = WriteGate::new(State::Boot);
        let mut lifecycle = Lifecycle::new();
        drive_to_steady(&mut lifecycle);
        gate.set(lifecycle.state());
        assert_eq!(lifecycle.state(), State::Steady);
        assert_eq!(gate.check(), Ok(()));

        let actions = drive(&gate, &mut lifecycle, Event::Signal(Sig::Int));
        assert_eq!(lifecycle.state(), State::Unmounting);
        assert_eq!(lifecycle.exit_code(), EXIT_OK);
        assert_eq!(gate.check(), Err(Errno(libc::ENOTCONN)));
        assert_eq!(actions[0], Action::CloseWriteGate);
    }

    /// 41 §6.1: a failed unmount is a resident read-only state, never exit 2.
    #[test]
    fn u_lifecycle_degraded_read_only() {
        let gate = WriteGate::new(State::Boot);
        let mut lifecycle = Lifecycle::new();
        drive_to_steady(&mut lifecycle);
        gate.set(lifecycle.state());

        drive(&gate, &mut lifecycle, Event::Disconnected(Cause::Reset));
        drive(&gate, &mut lifecycle, Event::FlushDone);
        let actions = drive(
            &gate,
            &mut lifecycle,
            Event::UnmountTried(Err(UnmountError::Exhausted)),
        );

        assert_eq!(lifecycle.state(), State::DegradedReadOnly);
        assert_eq!(gate.check(), Err(Errno::EROFS));
        assert_eq!(actions, vec![Action::DegradeReadOnly]);
        assert!(!actions.iter().any(|a| matches!(a, Action::Exit(_))));

        // A second TERM in UNMOUNTING is the only forced exit.
        let mut lifecycle = Lifecycle::new();
        drive_to_steady(&mut lifecycle);
        lifecycle.on(Event::Disconnected(Cause::Eof));
        let actions = lifecycle.on(Event::Signal(Sig::Term));
        assert_eq!(lifecycle.state(), State::Exited);
        assert_eq!(lifecycle.exit_code(), EXIT_USAGE);
        assert_eq!(
            actions,
            vec![
                Action::Unmount,
                Action::ReleaseLock,
                Action::Exit(EXIT_USAGE)
            ]
        );
    }

    /// 41 §5.3: epoch change / rollback / gap returns to JOINING without
    /// leaving the process.
    #[test]
    fn u_lifecycle_resync_returns_to_joining() {
        let gate = WriteGate::new(State::Boot);
        let mut lifecycle = Lifecycle::new();
        drive_to_steady(&mut lifecycle);
        gate.set(lifecycle.state());

        for event in [
            Event::EpochChanged(2),
            Event::Resync(ResyncReason::Rollback),
            Event::Resync(ResyncReason::SeqGap),
        ] {
            let actions = drive(&gate, &mut lifecycle, event);
            assert_eq!(lifecycle.state(), State::Joining);
            assert_eq!(gate.check(), Err(Errno::EROFS));
            assert!(actions.contains(&Action::CloseWriteGate));
            assert!(actions.contains(&Action::StartJoin));
            assert!(!actions.iter().any(|a| matches!(a, Action::Exit(_))));

            drive(
                &gate,
                &mut lifecycle,
                Event::Joined(Ok(JoinOutcome {
                    epoch: 2,
                    covered: 100,
                })),
            );
            assert_eq!(lifecycle.state(), State::Steady);
            assert_eq!(gate.check(), Ok(()));
        }
    }

    /// 41 §6.2: resync-loop budget exhaustion is a disconnect exit.
    #[test]
    fn u_lifecycle_budget_expired_exits_ten() {
        let mut lifecycle = Lifecycle::new();
        drive_to_steady(&mut lifecycle);
        lifecycle.on(Event::BudgetExpired);
        assert_eq!(lifecycle.state(), State::Unmounting);
        assert_eq!(lifecycle.exit_code(), EXIT_DISCONNECTED);
        lifecycle.on(Event::FlushDone);
        let actions = lifecycle.on(Event::UnmountTried(Ok(())));
        assert_eq!(
            actions,
            vec![Action::ReleaseLock, Action::Exit(EXIT_DISCONNECTED)]
        );
    }

    /// 41 invariant 11 / 51 C-09: the gate mapping is explicit.
    #[test]
    fn u_lifecycle_write_gate_matrix() {
        let expected = [
            (State::Boot, Err(Errno(libc::ENOTCONN))),
            (State::Locked, Err(Errno(libc::ENOTCONN))),
            (State::Cleanup, Err(Errno(libc::ENOTCONN))),
            (State::Mounting, Err(Errno(libc::ENOTCONN))),
            (State::Joining, Err(Errno::EROFS)),
            (State::Steady, Ok(())),
            (State::Unmounting, Err(Errno(libc::ENOTCONN))),
            (State::DegradedReadOnly, Err(Errno::EROFS)),
            (State::Exited, Err(Errno(libc::ENOTCONN))),
        ];
        let gate = WriteGate::new(State::Boot);
        for (state, verdict) in expected {
            gate.set(state);
            assert_eq!(gate.check(), verdict, "state {state:?}");
            assert_eq!(gate.is_open(), verdict.is_ok());
            assert_eq!(gate.state(), state);
        }
    }

    /// The state names are the ones the status document promises.
    #[test]
    fn u_lifecycle_state_names() {
        let names: Vec<_> = State::ALL.iter().map(|state| state.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "BOOT",
                "LOCKED",
                "CLEANUP",
                "MOUNTING",
                "JOINING",
                "STEADY",
                "UNMOUNTING",
                "DEGRADED_RO",
                "EXITED",
            ]
        );
    }
}
