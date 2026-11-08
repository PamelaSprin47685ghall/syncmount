//! Server-side SQLite writer: one blocking thread owns the database.
//!
//! # Shape
//!
//! ```text
//! StoreHandle (async) --mpsc--> store thread: Db + State mirror + replay_wire
//! ```
//!
//! The async actor never runs SQL. It sends one batch of [`CommitRequest`]
//! values and awaits one [`CommitOutcome`] per request. The thread is the only
//! writer of the server database, so every batch is serial and the in-memory
//! [`State`] is never shared.
//!
//! # Group commit
//!
//! A batch is planned completely before SQLite sees a write:
//!
//! 1. Refuse a duplicate `op_id` before anything else. A retry must receive the
//!    original sequence number even when the operation would no longer plan.
//!    A duplicate against an earlier operation of the same batch is answered
//!    with that operation's freshly assigned sequence.
//! 2. Prepare the complete file bytes for `WRITE`, `PWRITE` and `TRUNCATE`
//!    against a staged [`State`] and an overlay of chunks that earlier
//!    operations of the same batch produced. A later `PWRITE` therefore sees
//!    an earlier `WRITE` even though neither is in SQLite yet.
//! 3. Plan each operation against the staged state. A rejection consumes no
//!    sequence and contributes no row.
//! 4. Run **one** SQLite transaction for every accepted operation: bump the
//!    sequence once per operation, write `replay_wire`, the chunks, the
//!    object/name rows, the event and the `op_id`. One `COMMIT` is one
//!    `synchronous=FULL` flush for the whole batch.
//! 5. Replace the in-memory state with the staged result.
//!
//! The whole batch commits or rolls back together. A failed transaction is
//! retried as a whole (not operation by operation) up to [`BATCH_ATTEMPTS`]
//! times: the plan is deterministic against the unchanged database, so a retry
//! preserves the sequence order the caller will broadcast. After the last
//! attempt every accepted operation reports [`CommitOutcome::Failed`] and the
//! caller may resend it; `op_id` idempotency makes that safe.
//!
//! # Crash recovery
//!
//! The event rows, `op_ids`, state rows and `replay_wire` frame of one batch
//! share one transaction. A crash before `COMMIT` loses the whole batch, so no
//! client could have observed an acknowledgement. A crash after `COMMIT`
//! keeps every event, so replay reproduces exactly what a live receiver saw.
//!
//! # Sidecar table
//!
//! `replay_wire` lives in the same database file but is not part of the core
//! schema. The store creates it on startup:
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS replay_wire (
//!   seq   INTEGER PRIMARY KEY,
//!   frame BLOB NOT NULL
//! ) STRICT, WITHOUT ROWID
//! ```
//!
//! # Locks
//!
//! Advisory locks are memory only: the server schema has no `locks` table.
//! [`State::commit`] still applies the lock changes, so a `LOCK` operation and
//! a `leave` event both keep the mirror correct.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rusqlite::{Connection, OptionalExtension, params};
use tokio::sync::{mpsc, oneshot};

use crate::protocol::messages::OpClass;
use crate::server::wire::{self, WireOp};
use crate::state::{self, Change, Chunk, Errno, Ino, Kind, ObjectPatch, Reject, State, Verdict};
use crate::store::sqlite::{
    self, ChunkRef, Db, EventDraft, EventRow, MetaValue, ObjectKind, ReadTx, RejectState, Role,
    WriteTx, keys,
};

pub use crate::store::sqlite::CompactReport;

/// How many commands the async handle may queue before it waits.
const COMMAND_CAPACITY: usize = 64;

/// Largest file the store will buffer in memory.
///
/// `PWRITE` and `TRUNCATE` need the complete post-operation file bytes, so the
/// whole file passes through one `Vec<u8>`. The documented server design point
/// is 4 GiB per file; a larger result is refused instead of risking an
/// allocation failure.
const MAX_FILE_BYTES: u64 = 4 << 30;

/// Whole-batch attempts before every accepted operation reports failure.
///
/// A group commit is retried as a unit, never operation by operation: the
/// staged plan is deterministic and the failed transaction rolled back, so the
/// retry keeps the sequence numbers the caller will broadcast in order.
const BATCH_ATTEMPTS: u32 = 3;

/// How long a chunk left without references must survive before a periodic
/// collection may delete it. Compaction-triggered collection uses no delay:
/// the compacted transaction has already dropped every event that could name
/// an orphan.
const GC_RETENTION_SECS: i64 = 3_600;

/// Minimum time between periodic collections on the store thread.
const GC_INTERVAL: Duration = Duration::from_secs(3_600);

const _: () = assert!(state::CHUNK_BYTES == sqlite::CHUNK_BYTES as u64);

/// Fixed metadata read at startup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreMeta {
    /// Current event epoch.
    pub epoch: i64,
    /// Last committed event sequence number.
    pub seq: i64,
    /// Oldest sequence number still replayable.
    pub replay_floor: i64,
    /// `seq` immediately before the last compaction; `0` if none.
    pub compacted_from_seq: i64,
    /// Epoch produced by the last compaction; `0` if none.
    pub compacted_epoch: i64,
    /// Last sequence of the compacted replay log; `0` if none.
    pub compacted_seq: i64,
    /// State digest recorded by the last compaction or clean shutdown.
    pub state_hash: [u8; 32],
}

/// The result of one commit attempt.
///
/// Equality compares the outcome and its sequence only. The committed event
/// and its content are carried for the broadcast path; tests assert the
/// sequence without rebuilding either.
#[derive(Clone, Debug)]
pub enum CommitOutcome {
    /// The operation was written at this sequence number.
    Applied {
        /// Assigned event sequence.
        seq: i64,
        /// The committed event, as the replay path reads it back.
        event: EventRow,
        /// Complete post-operation file bytes for `WRITE`, `PWRITE` and
        /// `TRUNCATE`; the live broadcast rebuilds its frame from these.
        content: Option<Vec<u8>>,
    },
    /// The state machine refused the operation; nothing was written.
    Rejected {
        /// The refusal to report to the client.
        reject: Reject,
    },
    /// The `op_id` was already committed; this is the original sequence.
    Duplicate {
        /// Sequence of the first commit.
        seq: i64,
    },
    /// The write failed; the transaction was rolled back.
    Failed {
        /// Human-readable failure for logs.
        message: String,
    },
}

impl PartialEq for CommitOutcome {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Applied { seq: left, .. }, Self::Applied { seq: right, .. }) => left == right,
            (Self::Rejected { reject: left }, Self::Rejected { reject: right }) => left == right,
            (Self::Duplicate { seq: left }, Self::Duplicate { seq: right }) => left == right,
            (Self::Failed { message: left }, Self::Failed { message: right }) => left == right,
            _ => false,
        }
    }
}

impl Eq for CommitOutcome {}

/// One operation submitted to the store thread.
#[derive(Clone, Debug)]
pub struct CommitRequest {
    /// Session that owns the operation.
    pub session: [u8; 16],
    /// Decoded operation.
    pub op: WireOp,
    /// Assembled `OP_DATA` for `WRITE`/`PWRITE`.
    pub content: Option<Vec<u8>>,
    /// Original encoded frame, with `header.seq = 0`.
    pub wire: Vec<u8>,
    /// Client-supplied creation timestamp, in Unix seconds.
    pub created_at: i64,
}

/// Async front end of the store thread.
///
/// Cloning shares the command channel and the join handle. The first
/// [`StoreHandle::shutdown`] to run takes the join handle; later calls still
/// observe a stopped thread and return its result.
#[derive(Clone)]
pub struct StoreHandle {
    tx: mpsc::Sender<StoreCmd>,
    join: Arc<Mutex<Option<std::thread::JoinHandle<()>>>>,
}

impl std::fmt::Debug for StoreHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreHandle").finish_non_exhaustive()
    }
}

/// One command for the store thread.
enum StoreCmd {
    CommitBatch {
        requests: Vec<CommitRequest>,
        reply: oneshot::Sender<Vec<CommitOutcome>>,
    },
    Leave {
        session: [u8; 16],
        wire: Vec<u8>,
        reply: oneshot::Sender<CommitOutcome>,
    },
    Events {
        epoch: i64,
        after: i64,
        limit: u32,
        reply: oneshot::Sender<Result<Vec<EventRow>, String>>,
    },
    Wire {
        seq: i64,
        reply: oneshot::Sender<Result<Option<Vec<u8>>, String>>,
    },
    ChunkData {
        hash: [u8; 32],
        reply: oneshot::Sender<Result<Option<Vec<u8>>, String>>,
    },
    PathState {
        path: String,
        reply: oneshot::Sender<Result<Option<RejectState>, String>>,
    },
    StateHash {
        reply: oneshot::Sender<Result<[u8; 32], String>>,
    },
    Compact {
        reply: oneshot::Sender<Result<CompactReport, String>>,
    },
    Shutdown {
        reply: oneshot::Sender<Result<(), String>>,
    },
}

impl StoreHandle {
    /// Open the database, load the mirror and start the writer thread.
    ///
    /// # Errors
    ///
    /// A database that cannot be opened, a state that breaks an invariant, or
    /// a thread that cannot be spawned.
    pub fn start(db_path: PathBuf) -> Result<(Self, StoreMeta), String> {
        let (tx, rx) = mpsc::channel(COMMAND_CAPACITY);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let join = std::thread::Builder::new()
            .name("syncmount-store".to_owned())
            .spawn(move || match StoreThread::open(&db_path) {
                Ok((store, meta)) => {
                    if ready_tx.send(Ok(meta)).is_ok() {
                        store.run(rx);
                    }
                }
                Err(message) => {
                    let _ = ready_tx.send(Err(message));
                }
            })
            .map_err(|err| format!("spawn store thread: {err}"))?;

        match ready_rx.recv() {
            Ok(Ok(meta)) => Ok((
                Self {
                    tx,
                    join: Arc::new(Mutex::new(Some(join))),
                },
                meta,
            )),
            Ok(Err(message)) => {
                let _ = join.join();
                Err(message)
            }
            Err(_) => {
                let _ = join.join();
                Err("store thread exited during startup".to_owned())
            }
        }
    }

    /// Plan, persist and apply one operation.
    pub async fn commit(&self, request: CommitRequest) -> CommitOutcome {
        let mut outcomes = self.commit_batch(vec![request]).await;
        outcomes.pop().unwrap_or_else(|| CommitOutcome::Failed {
            message: "store thread dropped the reply".to_owned(),
        })
    }

    /// Plan, persist and apply one group commit.
    ///
    /// Every request produces exactly one outcome in the same order. Accepted
    /// operations share one SQLite transaction and therefore one
    /// `synchronous=FULL` flush; a rejection, duplicate or per-operation
    /// preparation failure consumes no sequence and does not join the
    /// transaction.
    pub async fn commit_batch(&self, requests: Vec<CommitRequest>) -> Vec<CommitOutcome> {
        let count = requests.len();
        if count == 0 {
            return Vec::new();
        }
        let (reply, response) = oneshot::channel();
        if self
            .tx
            .send(StoreCmd::CommitBatch { requests, reply })
            .await
            .is_err()
        {
            return failed_batch(count, "store thread is gone");
        }
        match response.await {
            Ok(outcomes) if outcomes.len() == count => outcomes,
            Ok(outcomes) => failed_batch(
                count,
                &format!(
                    "store thread returned {} outcomes for {count} requests",
                    outcomes.len()
                ),
            ),
            Err(_) => failed_batch(count, "store thread dropped the reply"),
        }
    }

    /// Append a `leave` event and drop the session's advisory locks.
    pub async fn leave(&self, session: [u8; 16], wire: Vec<u8>) -> CommitOutcome {
        let (reply, response) = oneshot::channel();
        if self
            .tx
            .send(StoreCmd::Leave {
                session,
                wire,
                reply,
            })
            .await
            .is_err()
        {
            return CommitOutcome::Failed {
                message: "store thread is gone".to_owned(),
            };
        }
        match response.await {
            Ok(outcome) => outcome,
            Err(_) => CommitOutcome::Failed {
                message: "store thread dropped the reply".to_owned(),
            },
        }
    }

    /// Fold the event log and clear the replay sidecar.
    pub async fn compact(&self) -> Result<CompactReport, String> {
        let (reply, response) = oneshot::channel();
        self.tx
            .send(StoreCmd::Compact { reply })
            .await
            .map_err(|_| "store thread is gone".to_owned())?;
        response
            .await
            .map_err(|_| "store thread dropped the reply".to_owned())?
    }

    /// Read one page of events from `epoch`.
    pub async fn events(
        &self,
        epoch: i64,
        after: i64,
        limit: u32,
    ) -> Result<Vec<EventRow>, String> {
        let (reply, response) = oneshot::channel();
        self.tx
            .send(StoreCmd::Events {
                epoch,
                after,
                limit,
                reply,
            })
            .await
            .map_err(|_| "store thread is gone".to_owned())?;
        response
            .await
            .map_err(|_| "store thread dropped the reply".to_owned())?
    }

    /// Read the stored wire frame for one sequence number.
    pub async fn wire(&self, seq: i64) -> Result<Option<Vec<u8>>, String> {
        let (reply, response) = oneshot::channel();
        self.tx
            .send(StoreCmd::Wire { seq, reply })
            .await
            .map_err(|_| "store thread is gone".to_owned())?;
        response
            .await
            .map_err(|_| "store thread dropped the reply".to_owned())?
    }

    /// Read the authoritative state of one path for a point-to-point
    /// rejection. A missing object is reported as `object: None`.
    pub async fn path_state(&self, path: &str) -> Result<Option<RejectState>, String> {
        let (reply, response) = oneshot::channel();
        self.tx
            .send(StoreCmd::PathState {
                path: path.to_owned(),
                reply,
            })
            .await
            .map_err(|_| "store thread is gone".to_owned())?;
        response
            .await
            .map_err(|_| "store thread dropped the reply".to_owned())?
    }

    /// Read one chunk's plaintext bytes.
    pub async fn chunk_data(&self, hash: [u8; 32]) -> Result<Option<Vec<u8>>, String> {
        let (reply, response) = oneshot::channel();
        self.tx
            .send(StoreCmd::ChunkData { hash, reply })
            .await
            .map_err(|_| "store thread is gone".to_owned())?;
        response
            .await
            .map_err(|_| "store thread dropped the reply".to_owned())?
    }

    /// Compute the live state digest.
    pub async fn state_hash(&self) -> Result<[u8; 32], String> {
        let (reply, response) = oneshot::channel();
        self.tx
            .send(StoreCmd::StateHash { reply })
            .await
            .map_err(|_| "store thread is gone".to_owned())?;
        response
            .await
            .map_err(|_| "store thread dropped the reply".to_owned())?
    }

    /// Store the digest, stop the thread and join it.
    pub async fn shutdown(&self) -> Result<(), String> {
        let (reply, response) = oneshot::channel();
        let result = match self.tx.send(StoreCmd::Shutdown { reply }).await {
            Ok(()) => response
                .await
                .map_err(|_| "store thread dropped the shutdown reply".to_owned())?,
            Err(_) => Err("store thread is gone".to_owned()),
        };
        let join = {
            let mut guard = self
                .join
                .lock()
                .map_err(|_| "store join lock is poisoned".to_owned())?;
            guard.take()
        };
        if let Some(join) = join {
            join.join()
                .map_err(|_| "store thread panicked".to_owned())?;
        }
        result
    }
}

/// The blocking half: one database, one mirror, one sidecar connection.
struct StoreThread {
    db: Db,
    sidecar: Connection,
    state: State,
    meta: StoreMeta,
    /// Last successful orphan-chunk scan, for the periodic trigger.
    last_gc: Instant,
}

impl StoreThread {
    /// Open everything and rebuild the mirror from the database.
    fn open(path: &Path) -> Result<(Self, StoreMeta), String> {
        let db = Db::open(path, Role::Server).map_err(err_str)?;
        let sidecar = open_sidecar(db.path())?;
        let state = load_state(&db)?;
        state
            .check_invariants()
            .map_err(|reason| format!("in-memory state violates invariants: {reason}"))?;
        let meta = load_meta(&db)?;
        if meta.epoch < 1 {
            return Err(format!("meta.epoch is {}, expected at least 1", meta.epoch));
        }
        if meta.seq < 0 {
            return Err(format!(
                "meta.seq is {}, expected a non-negative value",
                meta.seq
            ));
        }
        if meta.replay_floor < 1 {
            return Err(format!(
                "meta.replay_floor is {}, expected at least 1",
                meta.replay_floor
            ));
        }
        let mut store = Self {
            db,
            sidecar,
            state,
            meta,
            last_gc: Instant::now(),
        };
        // Reclaim chunks orphaned by an earlier compaction before serving.
        store.gc_orphans(sqlite::now_secs() - GC_RETENTION_SECS, "startup");
        Ok((store, meta))
    }

    /// Serve commands until shutdown or until the handle is dropped.
    fn run(mut self, mut rx: mpsc::Receiver<StoreCmd>) {
        while let Some(command) = rx.blocking_recv() {
            match command {
                StoreCmd::CommitBatch { requests, reply } => {
                    let _ = reply.send(self.commit_batch(requests));
                }
                StoreCmd::Leave {
                    session,
                    wire,
                    reply,
                } => {
                    let _ = reply.send(self.leave(session, wire));
                }
                StoreCmd::Events {
                    epoch,
                    after,
                    limit,
                    reply,
                } => {
                    let _ = reply.send(self.events(epoch, after, limit));
                }
                StoreCmd::Wire { seq, reply } => {
                    let _ = reply.send(self.wire(seq));
                }
                StoreCmd::ChunkData { hash, reply } => {
                    let _ = reply.send(self.chunk_data(hash));
                }
                StoreCmd::PathState { path, reply } => {
                    let _ = reply.send(self.path_state(&path));
                }
                StoreCmd::StateHash { reply } => {
                    let _ = reply.send(self.state_hash());
                }
                StoreCmd::Compact { reply } => {
                    let _ = reply.send(self.compact());
                }
                StoreCmd::Shutdown { reply } => {
                    let _ = reply.send(self.shutdown());
                    break;
                }
            }
        }
    }

    /// Plan, persist and apply one group commit.
    ///
    /// Planning runs against a staged state; SQLite sees only the accepted
    /// operations and only after the whole batch has a sequence number. A
    /// rejection, duplicate or per-operation preparation failure never joins
    /// the transaction and never consumes a sequence.
    fn commit_batch(&mut self, requests: Vec<CommitRequest>) -> Vec<CommitOutcome> {
        let count = requests.len();
        if count == 0 {
            return Vec::new();
        }
        let read = match self.db.read() {
            Ok(read) => read,
            Err(err) => {
                return failed_batch(count, &format!("open batch read: {err}"));
            }
        };

        let mut outcomes: Vec<Option<CommitOutcome>> = (0..count).map(|_| None).collect();
        let mut accepted: Vec<AcceptedOp> = Vec::new();
        let mut staged = self.state.clone();
        let mut overlay: HashMap<[u8; 32], ChunkSource> = HashMap::new();
        let mut seen: HashMap<[u8; 16], i64> = HashMap::new();

        for (index, request) in requests.into_iter().enumerate() {
            let CommitRequest {
                session,
                op,
                content,
                wire,
                created_at,
            } = request;

            // A retry must return the original sequence even when the
            // operation would now be rejected (for example, a repeated
            // create). The same rule covers a retry inside one batch.
            if let Some(seq) = seen.get(&op.op_id) {
                outcomes[index] = Some(CommitOutcome::Duplicate { seq: *seq });
                continue;
            }
            match self.lookup_op_id(&read, op.op_id) {
                Ok(Some(seq)) => {
                    outcomes[index] = Some(CommitOutcome::Duplicate { seq });
                    continue;
                }
                Ok(None) => {}
                Err(message) => {
                    outcomes[index] = Some(CommitOutcome::Failed { message });
                    continue;
                }
            }

            let content =
                match self.prepare_content(&read, &staged, &overlay, &accepted, &op, content) {
                    Ok(content) => content,
                    Err(PrepareError::Reject(reject)) => {
                        outcomes[index] = Some(CommitOutcome::Rejected { reject });
                        continue;
                    }
                    Err(PrepareError::Failed(message)) => {
                        outcomes[index] = Some(CommitOutcome::Failed { message });
                        continue;
                    }
                };

            let planned = match wire::to_op(&op, content.as_deref(), &staged, session) {
                Ok(planned) => planned,
                Err(reject) => {
                    outcomes[index] = Some(CommitOutcome::Rejected { reject });
                    continue;
                }
            };

            let (changes, draft) = match &planned {
                Some(planned_op) => match state::plan(planned_op, &staged) {
                    Verdict::Apply(changes) => {
                        let draft = wire::event_for(&op, planned_op, &staged, session)
                            .with_created_at(created_at);
                        (changes, draft)
                    }
                    Verdict::Reject(reject) => {
                        outcomes[index] = Some(CommitOutcome::Rejected { reject });
                        continue;
                    }
                },
                None => (
                    Vec::new(),
                    EventDraft::sync_ctrl(op.op_id, 0).with_created_at(created_at),
                ),
            };

            let seq = match self
                .meta
                .seq
                .checked_add(i64::try_from(accepted.len()).unwrap_or(i64::MAX))
                .and_then(|seq| seq.checked_add(1))
            {
                Some(seq) => seq,
                None => {
                    outcomes[index] = Some(CommitOutcome::Failed {
                        message: "event sequence overflow".to_owned(),
                    });
                    continue;
                }
            };

            // Record where this operation's chunks live so a later PWRITE or
            // TRUNCATE in the same batch can read them before they reach
            // SQLite.
            if let Some(bytes) = content.as_deref() {
                record_chunk_sources(&mut overlay, accepted.len(), bytes, &changes);
            }
            staged.commit(changes.clone());
            seen.insert(op.op_id, seq);
            accepted.push(AcceptedOp {
                index,
                seq,
                op,
                created_at,
                draft,
                changes,
                content,
                wire,
            });
        }
        drop(read);

        if accepted.is_empty() {
            return finish_outcomes(outcomes);
        }

        let first_seq = self.meta.seq;
        match self.write_batch(&accepted) {
            Ok(events) => {
                let mut last = first_seq;
                for (op, event) in accepted.into_iter().zip(events) {
                    last = op.seq;
                    outcomes[op.index] = Some(CommitOutcome::Applied {
                        seq: op.seq,
                        event,
                        content: op.content,
                    });
                }
                self.meta.seq = last;
            }
            Err(message) => {
                // The transaction rolled back as a unit. Every accepted
                // operation failed; a duplicate that pointed into this batch
                // is no longer true because its target never committed.
                let message = format!("group commit failed after retries: {message}");
                for op in &accepted {
                    outcomes[op.index] = Some(CommitOutcome::Failed {
                        message: message.clone(),
                    });
                }
                for outcome in &mut outcomes {
                    if let Some(CommitOutcome::Duplicate { seq }) = outcome {
                        if *seq > first_seq {
                            *outcome = Some(CommitOutcome::Failed {
                                message: message.clone(),
                            });
                        }
                    }
                }
            }
        }
        if self.last_gc.elapsed() >= GC_INTERVAL {
            self.gc_orphans(sqlite::now_secs() - GC_RETENTION_SECS, "periodic");
        }
        finish_outcomes(outcomes)
    }

    /// Write one accepted batch in one SQLite transaction.
    ///
    /// Retried as a unit. A failed attempt rolls back and leaves `self.state`
    /// and `meta.seq` untouched, so the next attempt writes the same plan.
    fn write_batch(&mut self, accepted: &[AcceptedOp]) -> Result<Vec<EventRow>, String> {
        let mut last = String::new();
        for attempt in 0..BATCH_ATTEMPTS {
            match self.write_batch_once(accepted) {
                Ok(events) => return Ok(events),
                Err(message) => {
                    last = message;
                    if attempt + 1 < BATCH_ATTEMPTS {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        }
        Err(last)
    }

    /// One transaction attempt for the whole batch.
    fn write_batch_once(&mut self, accepted: &[AcceptedOp]) -> Result<Vec<EventRow>, String> {
        let tx = self
            .db
            .write()
            .map_err(|err| format!("begin batch: {err}"))?;
        let mut running = self.state.clone();
        let mut events = Vec::with_capacity(accepted.len());
        for op in accepted {
            let seq = tx.bump_seq().map_err(|err| format!("bump seq: {err}"))?;
            if seq != op.seq {
                return Err(format!(
                    "event sequence moved: expected {}, found {seq}",
                    op.seq
                ));
            }

            // The frame shares the batch transaction, so a replay reader can
            // never see an event whose original frame is missing.
            tx.conn()
                .execute(
                    "INSERT OR REPLACE INTO replay_wire (seq, frame) VALUES (?1, ?2)",
                    params![seq, op.wire.as_slice()],
                )
                .map_err(|err| format!("replay_wire write: {err}"))?;

            if let Some(bytes) = op.content.as_deref() {
                put_content_chunks(&tx, bytes, &op.changes)?;
            }

            let mut after = running.clone();
            after.commit(op.changes.clone());
            apply_rows(&tx, &running, &after, &op.changes, seq)?;

            let event = event_row(&op.draft, seq, self.meta.epoch)?;
            let inserted = match tx.insert_event(seq, op.draft.clone()) {
                Ok(inserted) => inserted,
                Err(sqlite::StoreError::DuplicateOp { existing, .. }) => {
                    return Err(format!(
                        "op_id {} was committed at {existing} during the batch",
                        hex::encode(op.op.op_id)
                    ));
                }
                Err(err) => return Err(format!("insert event: {err}")),
            };
            tx.record_op_id(op.op.op_id, inserted.payload_hash, seq, op.created_at)
                .map_err(|err| format!("record op_id: {err}"))?;
            events.push(event);
            running = after;
        }
        tx.commit().map_err(|err| format!("commit batch: {err}"))?;
        self.state = running;
        Ok(events)
    }

    /// Append a `leave` event. The caller supplies the encoded frame.
    fn leave(&mut self, session: [u8; 16], wire: Vec<u8>) -> CommitOutcome {
        let seq = match self.meta.seq.checked_add(1) {
            Some(seq) => seq,
            None => {
                return CommitOutcome::Failed {
                    message: "event sequence overflow".to_owned(),
                };
            }
        };

        let draft = EventDraft::leave(session);
        let event = match event_row(&draft, seq, self.meta.epoch) {
            Ok(event) => event,
            Err(message) => return CommitOutcome::Failed { message },
        };
        let tx = match self.db.write() {
            Ok(tx) => tx,
            Err(err) => {
                return CommitOutcome::Failed {
                    message: format!("begin leave: {err}"),
                };
            }
        };
        let bumped = match tx.bump_seq() {
            Ok(seq) => seq,
            Err(err) => {
                return CommitOutcome::Failed {
                    message: format!("bump seq: {err}"),
                };
            }
        };
        if bumped != seq {
            return CommitOutcome::Failed {
                message: format!("event sequence moved: expected {seq}, found {bumped}"),
            };
        }
        if let Err(err) = tx.conn().execute(
            "INSERT OR REPLACE INTO replay_wire (seq, frame) VALUES (?1, ?2)",
            params![seq, wire.as_slice()],
        ) {
            return CommitOutcome::Failed {
                message: format!("replay_wire write: {err}"),
            };
        }
        if let Err(err) = tx.insert_event(seq, draft) {
            return CommitOutcome::Failed {
                message: format!("insert leave event: {err}"),
            };
        }
        if let Err(err) = tx.commit() {
            return CommitOutcome::Failed {
                message: format!("commit leave: {err}"),
            };
        }

        self.state
            .commit(vec![Change::RemoveSessionLocks { session }]);
        self.meta.seq = seq;
        CommitOutcome::Applied {
            seq,
            event,
            content: None,
        }
    }

    /// Read the server's `op_ids` row for one operation.
    fn lookup_op_id(&self, read: &ReadTx, op_id: [u8; 16]) -> Result<Option<i64>, String> {
        Ok(read.op_id(op_id).map_err(err_str)?.map(|row| row.first_seq))
    }

    /// Build the complete post-operation file bytes.
    ///
    /// `WRITE` takes the supplied bytes as the whole file. `PWRITE` reads the
    /// old file, zero-fills any gap and patches the range. `TRUNCATE` and a
    /// size-changing `SETATTR` read the old file and resize it with zeros.
    /// Other classes need no content.
    fn prepare_content(
        &self,
        read: &ReadTx,
        state: &State,
        overlay: &HashMap<[u8; 32], ChunkSource>,
        accepted: &[AcceptedOp],
        op: &WireOp,
        content: Option<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>, PrepareError> {
        if op.class == OpClass::WRITE {
            let content = content
                .ok_or_else(|| PrepareError::Failed("WRITE carries no content".to_owned()))?;
            check_size(content.len() as u64)?;
            return Ok(Some(content));
        }

        if op.class == OpClass::PWRITE {
            let offset = op
                .offset
                .ok_or_else(|| PrepareError::Failed("PWRITE carries no offset".to_owned()))?;
            let patch = content
                .ok_or_else(|| PrepareError::Failed("PWRITE carries no content".to_owned()))?;
            let mut bytes = self.read_file_bytes(read, state, overlay, accepted, &op.path, None)?;
            // A zero-length write changes nothing; in particular it must not
            // extend the file to `offset`.
            if patch.is_empty() {
                return Ok(Some(bytes));
            }
            let end = offset
                .checked_add(patch.len() as u64)
                .ok_or_else(|| PrepareError::Reject(overflow_reject("pwrite end overflows")))?;
            check_size(end)?;
            let end = usize::try_from(end)
                .map_err(|_| PrepareError::Reject(overflow_reject("pwrite end exceeds usize")))?;
            let start = usize::try_from(offset).map_err(|_| {
                PrepareError::Reject(overflow_reject("pwrite offset exceeds usize"))
            })?;
            if bytes.len() < end {
                let extra = end - bytes.len();
                bytes.try_reserve_exact(extra).map_err(|_| {
                    PrepareError::Failed(format!("cannot buffer {end} bytes for PWRITE"))
                })?;
                bytes.resize(end, 0);
            }
            bytes[start..end].copy_from_slice(&patch);
            return Ok(Some(bytes));
        }

        if op.class == OpClass::TRUNCATE || op.class == OpClass::SETATTR {
            let length = match op.length {
                Some(length) => length,
                None if op.class == OpClass::SETATTR => return Ok(None),
                None => {
                    return Err(PrepareError::Failed(
                        "TRUNCATE carries no length".to_owned(),
                    ));
                }
            };
            check_size(length)?;
            if length == 0 {
                return Ok(Some(Vec::new()));
            }
            let mut bytes =
                self.read_file_bytes(read, state, overlay, accepted, &op.path, Some(length))?;
            let length = usize::try_from(length).map_err(|_| {
                PrepareError::Reject(overflow_reject("truncate length exceeds usize"))
            })?;
            if bytes.len() < length {
                let extra = length - bytes.len();
                bytes.try_reserve_exact(extra).map_err(|_| {
                    PrepareError::Failed(format!("cannot buffer {length} bytes for TRUNCATE"))
                })?;
                bytes.resize(length, 0);
            } else {
                bytes.truncate(length);
            }
            return Ok(Some(bytes));
        }

        Ok(None)
    }

    /// Read the current file bytes named by `path`.
    ///
    /// `limit` caps the number of bytes read. A shrinking `TRUNCATE` needs
    /// only the surviving prefix, so a large tail is never buffered.
    fn read_file_bytes(
        &self,
        read: &ReadTx,
        state: &State,
        overlay: &HashMap<[u8; 32], ChunkSource>,
        accepted: &[AcceptedOp],
        path: &str,
        limit: Option<u64>,
    ) -> Result<Vec<u8>, PrepareError> {
        let ino = state
            .resolve(path.as_bytes())
            .map_err(PrepareError::Reject)?;
        let refs = state.chunks(ino);

        let mut total = 0u64;
        for chunk in refs {
            total = total
                .checked_add(u64::from(chunk.len))
                .ok_or_else(|| PrepareError::Reject(overflow_reject("file size overflows u64")))?;
        }
        let wanted = limit.map_or(total, |limit| total.min(limit));
        check_size(wanted)?;
        let wanted = usize::try_from(wanted)
            .map_err(|_| PrepareError::Reject(overflow_reject("file size exceeds usize")))?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(wanted).map_err(|_| {
            PrepareError::Failed(format!("cannot buffer {wanted} bytes of file content"))
        })?;
        for chunk in refs {
            if bytes.len() >= wanted {
                break;
            }
            // A chunk produced by an earlier operation of this batch is not
            // in SQLite yet; its bytes live in that operation's content.
            let data: Cow<'_, [u8]> = if let Some(source) = overlay.get(&chunk.hash) {
                let source_op = &accepted[source.op];
                let content = source_op.content.as_deref().ok_or_else(|| {
                    PrepareError::Failed("batch chunk source has no buffered content".to_owned())
                })?;
                let end = source.offset.checked_add(source.len).ok_or_else(|| {
                    PrepareError::Failed("batch chunk range overflows".to_owned())
                })?;
                Cow::Borrowed(content.get(source.offset..end).ok_or_else(|| {
                    PrepareError::Failed("batch chunk range exceeds content".to_owned())
                })?)
            } else {
                let row = read
                    .chunk(chunk.hash)
                    .map_err(|err| PrepareError::Failed(format!("read chunk: {err}")))?
                    .ok_or_else(|| {
                        PrepareError::Failed(format!(
                            "chunk {} is missing",
                            hex::encode(chunk.hash)
                        ))
                    })?;
                Cow::Owned(row.data.ok_or_else(|| {
                    PrepareError::Failed(format!("chunk {} has no data", hex::encode(chunk.hash)))
                })?)
            };
            if data.len() != chunk.len as usize {
                return Err(PrepareError::Failed(format!(
                    "chunk {} is {} bytes, the list says {}",
                    hex::encode(chunk.hash),
                    data.len(),
                    chunk.len
                )));
            }
            let remaining = wanted - bytes.len();
            let take = remaining.min(data.len());
            bytes.extend_from_slice(&data[..take]);
        }
        Ok(bytes)
    }

    /// Read one page of events.
    fn events(&self, epoch: i64, after: i64, limit: u32) -> Result<Vec<EventRow>, String> {
        let read = self.db.read().map_err(err_str)?;
        read.events_from(epoch, after, limit).map_err(err_str)
    }

    /// Read the replay frame for one sequence number.
    fn wire(&self, seq: i64) -> Result<Option<Vec<u8>>, String> {
        self.sidecar
            .query_row(
                "SELECT frame FROM replay_wire WHERE seq = ?1",
                [seq],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(err_str)
    }

    /// Read the authoritative state of one path.
    fn path_state(&self, path: &str) -> Result<Option<RejectState>, String> {
        let read = self.db.read().map_err(err_str)?;
        let object = read.object_by_path(path).map_err(err_str)?;
        let Some((parent_path, name)) = path.rsplit_once('/') else {
            return Ok(None);
        };
        let parent_path = if parent_path.is_empty() {
            "/"
        } else {
            parent_path
        };
        let parent = if parent_path == "/" {
            Some(sqlite::ROOT_INO)
        } else {
            read.object_by_path(parent_path)
                .map_err(err_str)?
                .map(|object| object.ino)
        };
        let chunks = match &object {
            Some(object) => read.object_chunks(object.ino).map_err(err_str)?,
            None => Vec::new(),
        };
        let mut data = Vec::with_capacity(chunks.len());
        for chunk in &chunks {
            let bytes = read
                .conn()
                .query_row(
                    "SELECT data FROM chunks WHERE hash = ?1",
                    [chunk.hash.as_slice()],
                    |row| row.get::<_, Option<Vec<u8>>>(0),
                )
                .optional()
                .map_err(err_str)?
                .flatten()
                .unwrap_or_default();
            data.push(bytes);
        }
        Ok(Some(RejectState {
            path: path.to_owned(),
            object,
            chunks,
            data,
            parent,
            name: Some(name.to_owned()),
        }))
    }

    /// Read one chunk's bytes.
    fn chunk_data(&self, hash: [u8; 32]) -> Result<Option<Vec<u8>>, String> {
        let read = self.db.read().map_err(err_str)?;
        Ok(read
            .chunk(hash)
            .map_err(err_str)?
            .and_then(|chunk| chunk.data))
    }

    /// Compute the live digest of the tree.
    fn state_hash(&self) -> Result<[u8; 32], String> {
        let read = self.db.read().map_err(err_str)?;
        read.state_hash().map_err(err_str)
    }

    /// Fold the event log and clear the replay sidecar.
    fn compact(&mut self) -> Result<CompactReport, String> {
        // Clear the sidecar first. An empty sidecar is safe: replay
        // synthesizes a frame from the payload when no row exists. A stale row
        // at a sequence that the new epoch reuses would replay old content, so
        // it must never survive a successful compaction.
        self.sidecar
            .execute("DELETE FROM replay_wire", [])
            .map_err(|err| format!("clear replay_wire: {err}"))?;
        let report = self.db.compact().map_err(err_str)?;
        self.refresh_meta()?;
        // Every event that could have named an orphan is gone, so the
        // retention window is satisfied by the compaction itself.
        self.gc_orphans(sqlite::now_secs(), "compaction");
        Ok(report)
    }

    /// Delete chunks that no object, event or replay frame can need.
    ///
    /// A maintenance step: a failure is logged and does not fail the caller.
    fn gc_orphans(&mut self, older_than: i64, reason: &str) {
        let tx = match self.db.write() {
            Ok(tx) => tx,
            Err(err) => {
                tracing::warn!(event = "chunk_gc", reason, %err, "cannot begin chunk collection");
                return;
            }
        };
        let report = match tx.gc_orphan_chunks(older_than) {
            Ok(report) => report,
            Err(err) => {
                tracing::warn!(event = "chunk_gc", reason, %err, "chunk collection failed");
                return;
            }
        };
        if let Err(err) = tx.commit() {
            tracing::warn!(event = "chunk_gc", reason, %err, "cannot commit chunk collection");
            return;
        }
        self.last_gc = Instant::now();
        if report.orphans > 0 || report.deleted > 0 {
            tracing::info!(
                event = "chunk_gc",
                reason,
                orphans = report.orphans,
                deleted = report.deleted,
                freed_bytes = report.freed_bytes,
                "orphan chunk collection finished; freed pages are reused by later writes"
            );
        }
    }

    /// Store the state digest on clean shutdown.
    fn shutdown(&mut self) -> Result<(), String> {
        let tx = self.db.write().map_err(err_str)?;
        let hash = tx.state_hash().map_err(err_str)?;
        tx.set_meta_blob(keys::STATE_HASH, &hash).map_err(err_str)?;
        tx.commit().map_err(err_str)?;
        self.meta.state_hash = hash;
        Ok(())
    }

    /// Reload the metadata after compaction.
    fn refresh_meta(&mut self) -> Result<(), String> {
        let meta = load_meta(&self.db)?;
        self.meta = meta;
        Ok(())
    }
}

/// A content-preparation failure.
enum PrepareError {
    /// The operation is refused; no sequence is consumed.
    Reject(Reject),
    /// The store cannot build the content; nothing is written.
    Failed(String),
}

/// One accepted operation inside a group commit.
struct AcceptedOp {
    /// Position in the caller's request list, for the reply.
    index: usize,
    /// Event sequence assigned by this batch.
    seq: i64,
    /// Decoded operation.
    op: WireOp,
    /// Client-supplied creation timestamp.
    created_at: i64,
    /// Event to append.
    draft: EventDraft,
    /// State-machine changes for this operation.
    changes: Vec<Change>,
    /// Complete post-operation file bytes, if any.
    content: Option<Vec<u8>>,
    /// Original frame, stored in `replay_wire` inside the batch transaction.
    wire: Vec<u8>,
}

/// Where a chunk produced by an earlier operation of the same batch lives.
struct ChunkSource {
    /// Index into the batch's accepted list.
    op: usize,
    /// Byte offset inside that operation's content.
    offset: usize,
    /// Plaintext length.
    len: usize,
}

/// Build the outcome vector for an empty or fully resolved batch.
fn finish_outcomes(outcomes: Vec<Option<CommitOutcome>>) -> Vec<CommitOutcome> {
    outcomes
        .into_iter()
        .map(|outcome| {
            outcome.unwrap_or_else(|| CommitOutcome::Failed {
                message: "store did not resolve the operation".to_owned(),
            })
        })
        .collect()
}

/// One failure message for every request in a batch.
fn failed_batch(count: usize, message: &str) -> Vec<CommitOutcome> {
    (0..count)
        .map(|_| CommitOutcome::Failed {
            message: message.to_owned(),
        })
        .collect()
}

/// Record the byte ranges of one accepted operation's content chunks.
///
/// The overlay never copies: a later operation reads the earlier operation's
/// `content` buffer directly. The first writer of a hash wins because equal
/// chunk hashes name equal plaintext.
fn record_chunk_sources(
    overlay: &mut HashMap<[u8; 32], ChunkSource>,
    op: usize,
    content: &[u8],
    changes: &[Change],
) {
    // The planned `UpdateChunks` list is the authoritative chunk list; it
    // already carries the hashes. Reusing it avoids hashing the content a
    // third time. An unexpected list falls back to splitting the bytes.
    let planned = planned_chunks(changes);
    let total: usize = planned.iter().map(|chunk| chunk.len as usize).sum();
    if total == content.len() {
        let mut offset = 0usize;
        for chunk in planned {
            overlay.entry(chunk.hash).or_insert(ChunkSource {
                op,
                offset,
                len: chunk.len as usize,
            });
            offset += chunk.len as usize;
        }
        return;
    }
    let chunk_bytes = state::CHUNK_BYTES as usize;
    let mut offset = 0usize;
    for piece in content.chunks(chunk_bytes) {
        let hash = *blake3::hash(piece).as_bytes();
        overlay.entry(hash).or_insert(ChunkSource {
            op,
            offset,
            len: piece.len(),
        });
        offset += piece.len();
    }
}

/// The chunk list one operation's changes install, if any.
fn planned_chunks(changes: &[Change]) -> &[Chunk] {
    changes
        .iter()
        .find_map(|change| match change {
            Change::UpdateChunks { chunks, .. } => Some(chunks.as_slice()),
            _ => None,
        })
        .unwrap_or(&[])
}

/// Build the stored event row of one draft.
fn event_row(draft: &EventDraft, seq: i64, epoch: i64) -> Result<EventRow, String> {
    Ok(EventRow {
        seq,
        epoch: draft.epoch.unwrap_or(epoch),
        op_id: draft.op_id,
        session_id: draft.session_id,
        kind: draft.payload.kind(),
        path: draft.path.clone(),
        path2: draft.path2.clone(),
        ino: draft.payload.ino(),
        payload: draft
            .payload
            .encode()
            .map_err(|err| format!("encode event payload: {err}"))?,
        result: draft.result.clone(),
        applied: true,
        created_at: draft.created_at,
    })
}

/// Open the sidecar connection and create the replay table.
fn open_sidecar(path: &Path) -> Result<Connection, String> {
    let connection = Connection::open(path).map_err(|err| format!("open replay sidecar: {err}"))?;
    connection
        .busy_timeout(Duration::from_millis(5_000))
        .map_err(err_str)?;
    let mode: String = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .map_err(err_str)?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(format!(
            "replay sidecar journal mode is {mode:?}, expected WAL"
        ));
    }
    connection
        .execute_batch("PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;")
        .map_err(err_str)?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS replay_wire (
               seq   INTEGER PRIMARY KEY,
               frame BLOB NOT NULL
             ) STRICT, WITHOUT ROWID",
        )
        .map_err(err_str)?;
    Ok(connection)
}

/// Read the fixed metadata.
fn load_meta(db: &Db) -> Result<StoreMeta, String> {
    let read = db.read().map_err(err_str)?;
    Ok(StoreMeta {
        epoch: read.meta_i64(keys::EPOCH).map_err(err_str)?,
        seq: read.meta_i64(keys::SEQ).map_err(err_str)?,
        replay_floor: read.meta_i64(keys::REPLAY_FLOOR).map_err(err_str)?,
        compacted_from_seq: optional_i64(&read, keys::COMPACTED_FROM_SEQ)?,
        compacted_epoch: optional_i64(&read, keys::COMPACTED_EPOCH)?,
        compacted_seq: optional_i64(&read, keys::COMPACTED_SEQ)?,
        state_hash: read_state_hash(&read)?,
    })
}

/// Read an integer meta value, treating a missing key as zero.
fn optional_i64(read: &ReadTx, key: &str) -> Result<i64, String> {
    match read.get_meta(key).map_err(err_str)? {
        Some(MetaValue::Integer(value)) => Ok(value),
        Some(_) => Err(format!("meta.{key} is not an integer")),
        None => Ok(0),
    }
}

/// Read `meta.state_hash` and check its width.
fn read_state_hash(read: &ReadTx) -> Result<[u8; 32], String> {
    let bytes = read.meta_blob(keys::STATE_HASH).map_err(err_str)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("meta.state_hash is {} bytes, expected 32", bytes.len()))
}

/// Rebuild the mirror by walking `names` from the root.
///
/// The walk detects a directory cycle, a directory with more than one name, a
/// name that points at a missing or deleted object, and a live object that no
/// name reaches.
fn load_state(db: &Db) -> Result<State, String> {
    let read = db.read().map_err(err_str)?;
    let root = read
        .object(sqlite::ROOT_INO)
        .map_err(err_str)?
        .ok_or_else(|| "root object is missing".to_owned())?;
    if sql_kind(root.kind)? != Kind::Dir {
        return Err("root object is not a directory".to_owned());
    }

    let mut state = State::new();
    state.commit(vec![Change::UpdateObject {
        ino: state::ROOT,
        patch: ObjectPatch {
            mode: Some(root.mode),
            uid: Some(root.uid),
            gid: Some(root.gid),
            mtime_ns: Some(
                u64::try_from(root.mtime_ns).map_err(|_| "root mtime is negative".to_owned())?,
            ),
            size: Some(root.size),
            file_root: Some(root.file_root),
            nlink: Some(root.nlink),
        },
    }]);

    let mut objects: BTreeMap<Ino, sqlite::Object> = BTreeMap::new();
    objects.insert(state::ROOT, root);
    let mut names: Vec<(Ino, Vec<u8>, Ino)> = Vec::new();
    let mut queue = VecDeque::from([(state::ROOT, "/".to_owned())]);
    let mut directories: BTreeSet<Ino> = BTreeSet::from([state::ROOT]);

    while let Some((directory, directory_path)) = queue.pop_front() {
        for entry in read.children(ino_bytes(directory)).map_err(err_str)? {
            let child = ino_from_bytes(entry.ino);
            if child == state::ROOT {
                return Err("the root has a name".to_owned());
            }
            let expected_path = join_path(&directory_path, &entry.name);
            if entry.path != expected_path {
                return Err(format!(
                    "name {:?} carries path {:?}, expected {:?}",
                    entry.name, entry.path, expected_path
                ));
            }
            if let std::collections::btree_map::Entry::Vacant(slot) = objects.entry(child) {
                let row = read
                    .object(entry.ino)
                    .map_err(err_str)?
                    .ok_or_else(|| format!("name {:?} points to a missing inode", entry.path))?;
                if row.deleted {
                    return Err(format!("name {:?} points to a deleted object", entry.path));
                }
                slot.insert(row);
            }
            if sql_kind(objects[&child].kind)? == Kind::Dir {
                if !directories.insert(child) {
                    return Err(format!(
                        "directory {:?} has more than one name or closes a cycle",
                        entry.path
                    ));
                }
                queue.push_back((child, expected_path));
            }
            names.push((directory, entry.name.into_bytes(), child));
        }
    }

    let live: i64 = read
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM objects WHERE deleted = 0",
            [],
            |row| row.get(0),
        )
        .map_err(err_str)?;
    let live = usize::try_from(live).map_err(|_| "live object count is negative".to_owned())?;
    if live != objects.len() {
        return Err(format!(
            "{live} live objects, but only {} are reachable by name",
            objects.len()
        ));
    }

    let mut changes = Vec::with_capacity(objects.len() + names.len());
    for (&ino, row) in &objects {
        if ino == state::ROOT {
            continue;
        }
        changes.push(Change::InsertObject(state_object(ino, row)?));
    }
    for (&ino, row) in &objects {
        if sql_kind(row.kind)? != Kind::File {
            continue;
        }
        let refs = read.object_chunks(ino_bytes(ino)).map_err(err_str)?;
        if u32::try_from(refs.len()).ok() != Some(row.block_count) {
            return Err(format!(
                "object {} has block_count {} but {} chunks",
                hex::encode(ino_bytes(ino)),
                row.block_count,
                refs.len()
            ));
        }
        let mut chunks = Vec::with_capacity(refs.len());
        for (index, chunk) in refs.iter().enumerate() {
            if chunk.chunk_no as usize != index {
                return Err(format!(
                    "object_chunks of {} are not contiguous",
                    hex::encode(ino_bytes(ino))
                ));
            }
            chunks.push(Chunk::new(chunk.hash, chunk.len));
        }
        changes.push(Change::UpdateChunks {
            ino,
            chunks,
            size: row.size,
            file_root: row.file_root,
        });
    }
    for (parent, name, child) in names {
        changes.push(Change::InsertName {
            parent,
            name,
            ino: child,
        });
    }
    state.commit(changes);
    Ok(state)
}

/// Apply the planned changes to SQLite.
/// Store the chunk rows of one operation's complete content.
///
/// The planned chunk list already names the hashes in order, so the common
/// path slices the content buffer and never re-hashes it. A list that does not
/// describe the buffer falls back to [`wire::split_chunks`], which recomputes
/// the hashes and therefore cannot write a mismatched chunk.
fn put_content_chunks(tx: &WriteTx<'_>, content: &[u8], changes: &[Change]) -> Result<(), String> {
    let planned = planned_chunks(changes);
    let total: usize = planned.iter().map(|chunk| chunk.len as usize).sum();
    if total == content.len() {
        let mut offset = 0usize;
        for chunk in planned {
            let end = offset + chunk.len as usize;
            tx.put_chunk(chunk.hash, chunk.len, Some(&content[offset..end]))
                .map_err(|err| format!("put chunk {}: {err}", hex::encode(chunk.hash)))?;
            offset = end;
        }
        return Ok(());
    }
    for (chunk, data) in wire::split_chunks(content) {
        tx.put_chunk(chunk.hash, chunk.len, Some(data.as_slice()))
            .map_err(|err| format!("put chunk {}: {err}", hex::encode(chunk.hash)))?;
    }
    Ok(())
}

fn apply_rows(
    tx: &WriteTx<'_>,
    before: &State,
    after: &State,
    changes: &[Change],
    seq: i64,
) -> Result<(), String> {
    let touched = touched_inos(changes);
    let inserted = inserted_inos(changes);

    // Objects first: names and object_chunks both reference `objects`.
    for &ino in &touched {
        if let Some(object) = after.object(ino) {
            let created_seq = if inserted.contains(&ino) { seq } else { 0 };
            let row = object_row(object, after.chunks(ino), created_seq, seq)?;
            tx.put_object(&row).map_err(err_str)?;
        } else if let Some(object) = before.object(ino) {
            // `RemoveObject` is a hard delete in the state machine. The server
            // keeps a tombstone instead, so the inode is never reused and old
            // events still resolve to a row.
            let row = tombstone_row(object, seq)?;
            tx.put_object(&row).map_err(err_str)?;
            tx.set_object_chunks(ino_bytes(ino), &[]).map_err(err_str)?;
        }
    }

    // Remove names before inserting, so a rename can reuse a path.
    for change in changes {
        if let Change::RemoveName { parent, name } = change {
            tx.delete_name(ino_bytes(*parent), name_str(name)?)
                .map_err(err_str)?;
        }
    }

    // Every inserted name rewrites the whole subtree under its inode. A
    // rename moves the directory itself and changes only the paths of its
    // descendants; their (parent, name) keys stay the same.
    for change in changes {
        let Change::InsertName { parent, name, ino } = change else {
            continue;
        };
        let path = child_path(after, *parent, name)?;
        let mut rows = Vec::new();
        collect_subtree(after, *parent, name_str(name)?, *ino, &path, &mut rows, 0)?;
        for row in &rows {
            tx.delete_name(ino_bytes(row.parent), &row.name)
                .map_err(err_str)?;
        }
        for row in &rows {
            tx.put_name(
                ino_bytes(row.parent),
                &row.name,
                ino_bytes(row.ino),
                &row.path,
            )
            .map_err(err_str)?;
        }
    }

    // Chunk lists last: `put_chunk` ran before this function.
    for &ino in &touched {
        if after.object(ino).is_some() {
            let refs = chunk_refs(after.chunks(ino))?;
            tx.set_object_chunks(ino_bytes(ino), &refs)
                .map_err(err_str)?;
        }
    }
    Ok(())
}

/// The inodes whose object rows this change list touches.
fn touched_inos(changes: &[Change]) -> BTreeSet<Ino> {
    let mut set = BTreeSet::new();
    for change in changes {
        match change {
            Change::InsertObject(object) => {
                set.insert(object.ino);
            }
            Change::UpdateObject { ino, .. }
            | Change::RemoveObject { ino }
            | Change::UpdateChunks { ino, .. }
            | Change::SetAttrs { ino, .. } => {
                set.insert(*ino);
            }
            Change::InsertName { parent, ino, .. } => {
                set.insert(*parent);
                set.insert(*ino);
            }
            Change::RemoveName { parent, .. } => {
                set.insert(*parent);
            }
            Change::InsertLock { .. }
            | Change::RemoveLocks { .. }
            | Change::RemoveSessionLocks { .. } => {}
        }
    }
    set
}

/// The inodes inserted by this change list.
fn inserted_inos(changes: &[Change]) -> BTreeSet<Ino> {
    changes
        .iter()
        .filter_map(|change| match change {
            Change::InsertObject(object) => Some(object.ino),
            _ => None,
        })
        .collect()
}

/// One `names` row with its full path.
struct NameRow {
    parent: Ino,
    name: String,
    ino: Ino,
    path: String,
}

/// Collect the name rows of one subtree in parent-before-child order.
fn collect_subtree(
    state: &State,
    parent: Ino,
    name: &str,
    ino: Ino,
    path: &str,
    rows: &mut Vec<NameRow>,
    depth: usize,
) -> Result<(), String> {
    if depth > state.len() {
        return Err("directory cycle while rewriting names".to_owned());
    }
    rows.push(NameRow {
        parent,
        name: name.to_owned(),
        ino,
        path: path.to_owned(),
    });
    if state.object(ino).map(|object| object.kind) != Some(Kind::Dir) {
        return Ok(());
    }
    for (child_name, child) in state.children(ino) {
        let child_name = name_str(child_name)?;
        let child_path = join_path(path, child_name);
        collect_subtree(state, ino, child_name, child, &child_path, rows, depth + 1)?;
    }
    Ok(())
}

/// The full path of one directory.
///
/// Directories have exactly one name, so the walk is unambiguous. The root is
/// `/`.
fn path_of(state: &State, ino: Ino) -> Result<String, String> {
    if ino == state::ROOT {
        return Ok("/".to_owned());
    }
    let mut segments: Vec<String> = Vec::new();
    let mut node = ino;
    let mut steps = 0usize;
    loop {
        if node == state::ROOT {
            break;
        }
        let parent = state
            .parent_of(node)
            .ok_or_else(|| format!("inode {} has no parent", hex::encode(ino_bytes(node))))?;
        let name = state
            .children(parent)
            .find(|(_, child)| *child == node)
            .map(|(name, _)| name.to_vec())
            .ok_or_else(|| {
                format!(
                    "parent {} does not list inode {}",
                    hex::encode(ino_bytes(parent)),
                    hex::encode(ino_bytes(node))
                )
            })?;
        segments
            .push(String::from_utf8(name).map_err(|_| "directory name is not UTF-8".to_owned())?);
        node = parent;
        steps += 1;
        if steps > state.len() {
            return Err("directory cycle while computing a path".to_owned());
        }
    }
    segments.reverse();
    let mut path = String::new();
    for segment in segments {
        path.push('/');
        path.push_str(&segment);
    }
    Ok(path)
}

/// The path of `name` inside `parent`.
fn child_path(state: &State, parent: Ino, name: &[u8]) -> Result<String, String> {
    let parent_path = path_of(state, parent)?;
    Ok(join_path(&parent_path, name_str(name)?))
}

/// Append one name to a directory path.
fn join_path(parent: &str, name: &str) -> String {
    let mut path = String::with_capacity(parent.len() + name.len() + 1);
    path.push_str(parent);
    if parent != "/" {
        path.push('/');
    }
    path.push_str(name);
    path
}

/// Borrow one name as UTF-8. The wire carries paths as strings.
fn name_str(name: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(name)
        .map_err(|_| format!("name {:?} is not UTF-8", String::from_utf8_lossy(name)))
}

/// Build the SQL row for a live state object.
fn object_row(
    object: &state::Object,
    chunks: &[Chunk],
    created_seq: i64,
    updated_seq: i64,
) -> Result<sqlite::Object, String> {
    Ok(sqlite::Object {
        ino: ino_bytes(object.ino),
        kind: kind_to_sql(object.kind),
        mode: object.mode,
        uid: object.uid,
        gid: object.gid,
        mtime_ns: i64::try_from(object.mtime_ns).map_err(|_| {
            format!(
                "mtime of {} does not fit i64",
                hex::encode(ino_bytes(object.ino))
            )
        })?,
        size: object.size,
        file_root: object.file_root,
        block_count: u32::try_from(chunks.len())
            .map_err(|_| "too many chunks for block_count".to_owned())?,
        target: object.target.clone(),
        nlink: object.nlink,
        deleted: false,
        created_seq,
        updated_seq,
    })
}

/// Build the SQL row for a removed object.
///
/// `block_count` is zero because the chunk list is cleared in the same
/// transaction. The other columns are preserved, as the contract asks.
fn tombstone_row(object: &state::Object, updated_seq: i64) -> Result<sqlite::Object, String> {
    Ok(sqlite::Object {
        ino: ino_bytes(object.ino),
        kind: kind_to_sql(object.kind),
        mode: object.mode,
        uid: object.uid,
        gid: object.gid,
        mtime_ns: i64::try_from(object.mtime_ns).map_err(|_| {
            format!(
                "mtime of {} does not fit i64",
                hex::encode(ino_bytes(object.ino))
            )
        })?,
        size: object.size,
        file_root: object.file_root,
        block_count: 0,
        target: object.target.clone(),
        nlink: 0,
        deleted: true,
        created_seq: 0,
        updated_seq,
    })
}

/// Build the SQL chunk references for one file.
fn chunk_refs(chunks: &[Chunk]) -> Result<Vec<ChunkRef>, String> {
    chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| {
            let chunk_no = u32::try_from(index).map_err(|_| "too many chunks".to_owned())?;
            Ok(ChunkRef {
                chunk_no,
                hash: chunk.hash,
                offset: u64::from(chunk_no) * u64::from(sqlite::CHUNK_BYTES),
                len: chunk.len,
            })
        })
        .collect()
}

/// Convert a state object kind to its SQL kind.
fn kind_to_sql(kind: Kind) -> ObjectKind {
    match kind {
        Kind::File => ObjectKind::File,
        Kind::Dir => ObjectKind::Dir,
        Kind::Symlink => ObjectKind::Symlink,
    }
}

/// Convert a SQL object kind to a state kind.
fn sql_kind(kind: ObjectKind) -> Result<Kind, String> {
    match kind {
        ObjectKind::File => Ok(Kind::File),
        ObjectKind::Dir => Ok(Kind::Dir),
        ObjectKind::Symlink => Ok(Kind::Symlink),
        other => Err(format!(
            "object kind {other} is not supported by the state machine"
        )),
    }
}

/// Convert one SQL object row to a state object.
fn state_object(ino: Ino, row: &sqlite::Object) -> Result<state::Object, String> {
    let mtime_ns = u64::try_from(row.mtime_ns)
        .map_err(|_| format!("mtime of {} is negative", hex::encode(ino_bytes(ino))))?;
    Ok(state::Object {
        ino,
        kind: sql_kind(row.kind)?,
        mode: row.mode,
        uid: row.uid,
        gid: row.gid,
        mtime_ns,
        size: row.size,
        file_root: row.file_root,
        nlink: row.nlink,
        target: row.target.clone(),
    })
}

/// Refuse a buffered file that exceeds the design point.
fn check_size(size: u64) -> Result<(), PrepareError> {
    if size > MAX_FILE_BYTES {
        return Err(PrepareError::Reject(overflow_reject(
            "file exceeds the 4 GiB buffering limit",
        )));
    }
    Ok(())
}

/// The rejection used for an unrepresentable size.
fn overflow_reject(reason: &'static str) -> Reject {
    Reject::new(Errno::EOVERFLOW, reason)
}

/// Encode an inode as its 16-byte little-endian key.
const fn ino_bytes(ino: Ino) -> [u8; 16] {
    ino.to_le_bytes()
}

/// Decode a 16-byte inode key.
const fn ino_from_bytes(bytes: [u8; 16]) -> Ino {
    Ino::from_le_bytes(bytes)
}

/// Format an error for the string boundary.
fn err_str(err: impl Display) -> String {
    err.to_string()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::protocol::frame::SessionId;
    use crate::protocol::messages::DataRef;
    use crate::store::sqlite::{EventKind, EventPayload};

    use tempfile::TempDir;

    fn ino_id(value: u8) -> [u8; 16] {
        let mut id = [0u8; 16];
        id[0] = value;
        id
    }

    /// A successful outcome for `seq`, compared by sequence only.
    fn applied(seq: i64) -> CommitOutcome {
        CommitOutcome::Applied {
            seq,
            event: EventRow {
                seq,
                epoch: 1,
                op_id: None,
                session_id: None,
                kind: EventKind::SyncCtrl,
                path: None,
                path2: None,
                ino: None,
                payload: EventPayload::SyncCtrl { code: 0 }.encode().unwrap(),
                result: "ok".to_owned(),
                applied: true,
                created_at: 0,
            },
            content: None,
        }
    }

    fn base(class: OpClass, path: &str) -> WireOp {
        WireOp {
            op_id: [0u8; 16],
            class,
            path: path.to_owned(),
            path2: None,
            target: None,
            mode: None,
            uid: 0,
            gid: 0,
            mtime_ns: 0,
            data: None,
            offset: None,
            length: None,
            lock_type: None,
            lock_action: None,
            lock_start: None,
            lock_len: None,
        }
    }

    fn data_ref(bytes: &[u8]) -> DataRef {
        DataRef {
            session: SessionId::ZERO,
            total_len: bytes.len() as u64,
            data_hash: *blake3::hash(bytes).as_bytes(),
        }
    }

    fn create_file(id: u8, path: &str) -> WireOp {
        let mut op = base(OpClass::CREATE_EXCL, path);
        op.op_id = ino_id(id);
        op.mode = Some(0o644);
        op.mtime_ns = 1_000;
        op
    }

    fn make_dir(id: u8, path: &str) -> WireOp {
        let mut op = base(OpClass::MKDIR, path);
        op.op_id = ino_id(id);
        op.mode = Some(0o755);
        op.mtime_ns = 1_000;
        op
    }

    fn write_op(id: u8, path: &str, content: &[u8]) -> (WireOp, Option<Vec<u8>>) {
        let mut op = base(OpClass::WRITE, path);
        op.op_id = ino_id(id);
        op.mtime_ns = 1_000 + u64::from(id);
        op.data = Some(data_ref(content));
        (op, Some(content.to_vec()))
    }

    fn pwrite_op(id: u8, path: &str, offset: u64, content: &[u8]) -> (WireOp, Option<Vec<u8>>) {
        let mut op = base(OpClass::PWRITE, path);
        op.op_id = ino_id(id);
        op.offset = Some(offset);
        op.mtime_ns = 1_000 + u64::from(id);
        op.data = Some(data_ref(content));
        (op, Some(content.to_vec()))
    }

    fn request(op: WireOp, content: Option<Vec<u8>>) -> CommitRequest {
        CommitRequest {
            session: [9u8; 16],
            op,
            content,
            wire: vec![0xAA, 0xBB],
            created_at: 1_700_000_000,
        }
    }

    fn start(dir: &TempDir) -> (StoreHandle, StoreMeta, PathBuf) {
        let path = dir.path().join("server.db");
        let (store, meta) = StoreHandle::start(path.clone()).unwrap();
        (store, meta, path)
    }

    #[tokio::test]
    async fn sequences_are_unique_and_monotonic() {
        let dir = tempfile::tempdir().unwrap();
        let (store, meta, _) = start(&dir);
        assert_eq!(meta.epoch, 1);
        assert_eq!(meta.seq, 0);
        assert_eq!(meta.replay_floor, 1);
        assert_eq!(meta.state_hash.len(), 32);

        let first = store.commit(request(create_file(1, "/a"), None)).await;
        assert_eq!(first, applied(1));
        let second = store.commit(request(create_file(2, "/b"), None)).await;
        assert_eq!(second, applied(2));

        let rows = store.events(1, 0, 10).await.unwrap();
        let seqs: Vec<i64> = rows.iter().map(|row| row.seq).collect();
        assert_eq!(seqs, vec![1, 2]);
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn commit_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path;
        {
            let (store, _, db_path) = start(&dir);
            path = db_path;
            assert_eq!(
                store.commit(request(create_file(1, "/f"), None)).await,
                applied(1)
            );
            let (op, content) = write_op(2, "/f", b"abc");
            assert_eq!(store.commit(request(op, content)).await, applied(2));
            store.shutdown().await.unwrap();
        }

        let (store, meta) = StoreHandle::start(path).unwrap();
        assert_eq!(meta.seq, 2);
        assert_eq!(meta.state_hash, store.state_hash().await.unwrap());

        let mut truncate = base(OpClass::TRUNCATE, "/f");
        truncate.op_id = ino_id(3);
        truncate.length = Some(1);
        truncate.mtime_ns = 2_000;
        assert_eq!(store.commit(request(truncate, None)).await, applied(3));
        let hash = *blake3::hash(b"a").as_bytes();
        assert_eq!(store.chunk_data(hash).await.unwrap(), Some(b"a".to_vec()));
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn duplicate_op_id_returns_first_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, _) = start(&dir);

        assert_eq!(
            store.commit(request(create_file(1, "/a"), None)).await,
            applied(1)
        );
        assert_eq!(
            store.commit(request(create_file(1, "/a"), None)).await,
            CommitOutcome::Duplicate { seq: 1 }
        );
        assert_eq!(
            store.commit(request(create_file(2, "/b"), None)).await,
            applied(2)
        );
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn rejected_plan_consumes_no_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, _) = start(&dir);

        let mut unlink = base(OpClass::UNLINK, "/missing");
        unlink.op_id = ino_id(1);
        unlink.mtime_ns = 1_000;
        let outcome = store.commit(request(unlink, None)).await;
        assert!(matches!(
            outcome,
            CommitOutcome::Rejected { reject } if reject.errno == Errno::ENOENT
        ));
        assert!(store.wire(1).await.unwrap().is_none());

        assert_eq!(
            store.commit(request(create_file(2, "/f"), None)).await,
            applied(1)
        );
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn compact_bumps_epoch_and_clears_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, path) = start(&dir);
        assert_eq!(
            store.commit(request(create_file(1, "/f"), None)).await,
            applied(1)
        );
        let (op, content) = write_op(2, "/f", b"x");
        assert_eq!(store.commit(request(op, content)).await, applied(2));

        let report = store.compact().await.unwrap();
        assert_eq!(report.epoch, 2);
        assert_eq!(report.from_seq, 2);
        assert_eq!(report.compacted_seq, report.events as i64);
        assert!(report.events >= 3);
        assert!(store.events(1, 0, 10).await.is_err());
        let rows = store.events(2, 0, 1_000).await.unwrap();
        assert_eq!(rows.len() as u64, report.events);
        assert!(store.wire(1).await.unwrap().is_none());
        store.shutdown().await.unwrap();

        let (store, meta) = StoreHandle::start(path).unwrap();
        assert_eq!(meta.epoch, 2);
        assert_eq!(meta.seq, report.events as i64);
        assert_eq!(meta.replay_floor, 1);
        assert_eq!(meta.compacted_from_seq, 2);
        assert_eq!(meta.compacted_epoch, 2);
        assert_eq!(meta.compacted_seq, report.compacted_seq);
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn compaction_collects_orphan_chunks_and_keeps_replayable_ones() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, path) = start(&dir);

        assert_eq!(
            store.commit(request(create_file(1, "/keep"), None)).await,
            applied(1)
        );
        let (op, content) = write_op(2, "/keep", b"keep");
        assert_eq!(store.commit(request(op, content)).await, applied(2));
        assert_eq!(
            store.commit(request(create_file(3, "/drop"), None)).await,
            applied(3)
        );
        let (op, content) = write_op(4, "/drop", b"drop");
        assert_eq!(store.commit(request(op, content)).await, applied(4));
        let mut unlink = base(OpClass::UNLINK, "/drop");
        unlink.op_id = ino_id(5);
        assert_eq!(store.commit(request(unlink, None)).await, applied(5));

        let keep_hash = sqlite::chunk_hash(b"keep");
        let drop_hash = sqlite::chunk_hash(b"drop");
        {
            let conn = Connection::open(&path).unwrap();
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM chunks WHERE hash = ?1",
                    [drop_hash.as_slice()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "the dropped file's chunk exists before compaction");
        }

        let report = store.compact().await.unwrap();
        assert!(report.epoch >= 2);

        {
            let conn = Connection::open(&path).unwrap();
            let count = |hash: [u8; 32]| -> i64 {
                conn.query_row(
                    "SELECT COUNT(*) FROM chunks WHERE hash = ?1",
                    [hash.as_slice()],
                    |row| row.get(0),
                )
                .unwrap()
            };
            assert_eq!(count(keep_hash), 1, "a live object keeps its chunk");
            assert_eq!(count(drop_hash), 0, "an unreferenced chunk is collected");
        }

        // The compacted log still describes the live file, and its bytes are
        // available to a replaying client.
        let rows = store.events(report.epoch, 0, 1_000).await.unwrap();
        assert!(rows.iter().any(|row| {
            row.kind == EventKind::Write && row.path.as_deref() == Some("/keep")
        }));
        assert_eq!(
            store.chunk_data(keep_hash).await.unwrap(),
            Some(b"keep".to_vec())
        );
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn sidecar_orphan_is_tolerated() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, path) = start(&dir);
        store.shutdown().await.unwrap();

        {
            let connection = Connection::open(&path).unwrap();
            connection
                .execute(
                    "INSERT INTO replay_wire (seq, frame) VALUES (?1, ?2)",
                    rusqlite::params![99i64, vec![7u8; 4]],
                )
                .unwrap();
        }

        let (store, meta) = StoreHandle::start(path).unwrap();
        assert_eq!(meta.seq, 0);
        assert_eq!(
            store.commit(request(create_file(1, "/f"), None)).await,
            applied(1)
        );
        assert_eq!(store.wire(99).await.unwrap(), Some(vec![7u8; 4]));
        assert_eq!(store.wire(1).await.unwrap(), Some(vec![0xAA, 0xBB]));
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_rolled_back_compaction_leaves_the_watermarks_alone() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, path) = start(&dir);
        assert_eq!(
            store.commit(request(create_file(1, "/f"), None)).await,
            applied(1)
        );
        store.shutdown().await.unwrap();
        drop(store);

        let mut db = Db::open(&path, Role::Server).unwrap();
        {
            let tx = db.write().unwrap();
            let report = tx.compact().unwrap();
            assert_eq!(report.epoch, 2);
            assert_eq!(report.from_seq, 1);
            // Dropping without a commit rolls the whole compaction back,
            // exactly as a crash before the commit would. No client may see
            // a new epoch or a fast-forward point.
        }
        let read = db.read().unwrap();
        assert_eq!(read.meta_i64(keys::EPOCH).unwrap(), 1);
        assert_eq!(read.meta_i64(keys::SEQ).unwrap(), 1);
        assert!(read.get_meta(keys::COMPACTED_FROM_SEQ).unwrap().is_none());
        assert!(read.get_meta(keys::COMPACTED_EPOCH).unwrap().is_none());
        assert!(read.get_meta(keys::COMPACTED_SEQ).unwrap().is_none());
        assert!(read.object_by_path("/f").unwrap().is_some());
    }

    #[tokio::test]
    async fn pwrite_patches_the_old_content() {
        let dir = tempfile::tempdir().unwrap();
        let (store, meta, _) = start(&dir);
        assert_eq!(
            store.commit(request(create_file(1, "/f"), None)).await,
            applied(1)
        );
        let (op, content) = write_op(2, "/f", b"hello world");
        assert_eq!(store.commit(request(op, content)).await, applied(2));

        let (op, patch) = pwrite_op(3, "/f", 6, b"there");
        assert_eq!(store.commit(request(op, patch)).await, applied(3));
        let rows = store.events(meta.epoch, 2, 10).await.unwrap();
        let row = rows.iter().find(|row| row.seq == 3).unwrap();
        match row.decode().unwrap() {
            EventPayload::Write {
                offset, len, size, ..
            } => assert_eq!((offset, len, size), (6, 5, 11)),
            other => panic!("expected a write payload, got {other:?}"),
        }
        for (chunk, data) in wire::split_chunks(b"hello there") {
            assert_eq!(store.chunk_data(chunk.hash).await.unwrap(), Some(data));
        }

        let (op, patch) = pwrite_op(4, "/f", 11, b"!");
        assert_eq!(store.commit(request(op, patch)).await, applied(4));
        for (chunk, data) in wire::split_chunks(b"hello there!") {
            assert_eq!(store.chunk_data(chunk.hash).await.unwrap(), Some(data));
        }
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn rename_rewrites_the_whole_subtree() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, path) = start(&dir);
        assert_eq!(
            store.commit(request(make_dir(1, "/a"), None)).await,
            applied(1)
        );
        assert_eq!(
            store.commit(request(create_file(2, "/a/f"), None)).await,
            applied(2)
        );
        let (op, content) = write_op(3, "/a/f", b"x");
        assert_eq!(store.commit(request(op, content)).await, applied(3));

        let mut rename = base(OpClass::RENAME, "/a");
        rename.op_id = ino_id(4);
        rename.path2 = Some("/b".to_owned());
        rename.mtime_ns = 2_000;
        assert_eq!(store.commit(request(rename, None)).await, applied(4));
        store.shutdown().await.unwrap();

        let db = Db::open(&path, Role::Server).unwrap();
        let read = db.read().unwrap();
        assert!(read.object_by_path("/b").unwrap().is_some());
        assert!(read.object_by_path("/b/f").unwrap().is_some());
        assert!(read.object_by_path("/a").unwrap().is_none());
        assert!(read.object_by_path("/a/f").unwrap().is_none());
        let stale: i64 = read
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM names WHERE path = '/a' OR path LIKE '/a/%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stale, 0);
    }

    #[tokio::test]
    async fn truncate_grows_with_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let (store, meta, _) = start(&dir);
        assert_eq!(
            store.commit(request(create_file(1, "/f"), None)).await,
            applied(1)
        );
        let (op, content) = write_op(2, "/f", b"ab");
        assert_eq!(store.commit(request(op, content)).await, applied(2));

        let mut truncate = base(OpClass::TRUNCATE, "/f");
        truncate.op_id = ino_id(3);
        truncate.length = Some(5);
        truncate.mtime_ns = 2_000;
        assert_eq!(store.commit(request(truncate, None)).await, applied(3));

        let rows = store.events(meta.epoch, 2, 10).await.unwrap();
        match rows[0].decode().unwrap() {
            EventPayload::Truncate { size, .. } => assert_eq!(size, 5),
            other => panic!("expected a truncate payload, got {other:?}"),
        }
        for (chunk, data) in wire::split_chunks(b"ab\0\0\0") {
            assert_eq!(store.chunk_data(chunk.hash).await.unwrap(), Some(data));
        }
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn setattr_size_and_mode_commit_one_event() {
        let dir = tempfile::tempdir().unwrap();
        let (store, meta, _) = start(&dir);
        assert_eq!(
            store.commit(request(create_file(1, "/f"), None)).await,
            applied(1)
        );
        let (op, content) = write_op(2, "/f", b"abcdef");
        assert_eq!(store.commit(request(op, content)).await, applied(2));

        let mut setattr = base(OpClass::SETATTR, "/f");
        setattr.op_id = ino_id(3);
        setattr.mode = Some(0o600);
        setattr.length = Some(4);
        setattr.mtime_ns = 2_000;
        assert_eq!(store.commit(request(setattr, None)).await, applied(3));

        let rows = store.events(meta.epoch, 2, 10).await.unwrap();
        assert_eq!(rows.len(), 1, "size and mode are one event");
        match rows[0].decode().unwrap() {
            EventPayload::Setattr {
                size,
                mode,
                mtime_ns,
                ..
            } => {
                assert_eq!(size, Some(4));
                assert_eq!(mode, Some(0o600));
                assert_eq!(mtime_ns, Some(2_000));
            }
            other => panic!("expected a setattr payload, got {other:?}"),
        }
        let state = store.path_state("/f").await.unwrap().unwrap();
        let object = state.object.expect("server object");
        assert_eq!(object.size, 4);
        assert_eq!(object.mode, 0o600);
        for (chunk, data) in wire::split_chunks(b"abcd") {
            assert_eq!(store.chunk_data(chunk.hash).await.unwrap(), Some(data));
        }
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn leave_appends_an_event_and_drops_locks() {
        let dir = tempfile::tempdir().unwrap();
        let (store, meta, _) = start(&dir);
        let holder = [9u8; 16];
        let other = [8u8; 16];
        assert_eq!(
            store.commit(request(create_file(1, "/f"), None)).await,
            applied(1)
        );

        let mut lock = base(OpClass::FCNTL_LOCK, "/f");
        lock.op_id = ino_id(2);
        lock.lock_type = Some(1);
        lock.lock_action = Some(0);
        lock.lock_start = Some(0);
        lock.lock_len = Some(0);
        lock.mtime_ns = 1_000;
        assert_eq!(store.commit(request(lock, None)).await, applied(2));

        let mut conflict = base(OpClass::FCNTL_LOCK, "/f");
        conflict.op_id = ino_id(3);
        conflict.lock_type = Some(1);
        conflict.lock_action = Some(0);
        conflict.lock_start = Some(0);
        conflict.lock_len = Some(0);
        conflict.mtime_ns = 1_000;
        let mut conflict_request = request(conflict, None);
        conflict_request.session = other;
        assert!(matches!(
            store.commit(conflict_request).await,
            CommitOutcome::Rejected { reject } if reject.errno == Errno::EAGAIN
        ));

        assert_eq!(store.leave(holder, vec![0xCC]).await, applied(3));
        let rows = store.events(meta.epoch, 2, 10).await.unwrap();
        assert_eq!(rows[0].kind, EventKind::Leave);
        assert_eq!(rows[0].session_id, Some(holder));
        assert_eq!(store.wire(3).await.unwrap(), Some(vec![0xCC]));

        let mut retry = base(OpClass::FCNTL_LOCK, "/f");
        retry.op_id = ino_id(4);
        retry.lock_type = Some(1);
        retry.lock_action = Some(0);
        retry.lock_start = Some(0);
        retry.lock_len = Some(0);
        retry.mtime_ns = 1_000;
        let mut retry_request = request(retry, None);
        retry_request.session = other;
        assert_eq!(store.commit(retry_request).await, applied(4));
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn group_commit_assigns_consecutive_sequences_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path;
        {
            let (store, _, db_path) = start(&dir);
            path = db_path;
            let outcomes = store
                .commit_batch(vec![
                    request(create_file(1, "/a"), None),
                    request(create_file(2, "/b"), None),
                    request(create_file(3, "/c"), None),
                ])
                .await;
            assert_eq!(outcomes.len(), 3);
            for (index, outcome) in outcomes.iter().enumerate() {
                assert_eq!(*outcome, applied(index as i64 + 1));
            }
            let rows = store.events(1, 0, 10).await.unwrap();
            assert_eq!(
                rows.iter().map(|row| row.seq).collect::<Vec<_>>(),
                vec![1, 2, 3]
            );
            // The replay frame shares the batch transaction.
            assert_eq!(store.wire(3).await.unwrap(), Some(vec![0xAA, 0xBB]));
            store.shutdown().await.unwrap();
        }

        let (store, meta) = StoreHandle::start(path).unwrap();
        assert_eq!(meta.seq, 3);
        for path in ["/a", "/b", "/c"] {
            assert!(
                store
                    .path_state(path)
                    .await
                    .unwrap()
                    .unwrap()
                    .object
                    .is_some(),
                "{path} must survive the committed batch"
            );
        }
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn group_commit_rejects_without_consuming_a_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, _) = start(&dir);
        let outcomes = store
            .commit_batch(vec![
                request(create_file(1, "/a"), None),
                // A different op_id for an existing path: a plan rejection,
                // not a duplicate.
                request(create_file(2, "/a"), None),
                request(create_file(3, "/b"), None),
            ])
            .await;
        assert_eq!(outcomes[0], applied(1));
        assert!(matches!(
            &outcomes[1],
            CommitOutcome::Rejected { reject } if reject.errno == Errno::EEXIST
        ));
        assert_eq!(outcomes[2], applied(2));
        let rows = store.events(1, 0, 10).await.unwrap();
        assert_eq!(
            rows.iter().map(|row| row.seq).collect::<Vec<_>>(),
            vec![1, 2]
        );
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn group_commit_stages_content_for_later_operations() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, _) = start(&dir);
        let (write, content) = write_op(2, "/f", b"abc");
        let (patch, patch_content) = pwrite_op(3, "/f", 1, b"XY");
        let outcomes = store
            .commit_batch(vec![
                request(create_file(1, "/f"), None),
                request(write, content),
                request(patch, patch_content),
            ])
            .await;
        assert_eq!(outcomes[0], applied(1));
        assert_eq!(outcomes[1], applied(2));
        assert_eq!(outcomes[2], applied(3));

        let state = store.path_state("/f").await.unwrap().unwrap();
        assert_eq!(state.object.expect("file object").size, 3);
        let hash = *blake3::hash(b"aXY").as_bytes();
        assert_eq!(store.chunk_data(hash).await.unwrap(), Some(b"aXY".to_vec()));
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn group_commit_answers_an_in_batch_duplicate_with_the_first_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, _) = start(&dir);
        let outcomes = store
            .commit_batch(vec![
                request(create_file(1, "/a"), None),
                request(create_file(1, "/a"), None),
            ])
            .await;
        assert_eq!(outcomes[0], applied(1));
        assert_eq!(outcomes[1], CommitOutcome::Duplicate { seq: 1 });
        assert_eq!(store.events(1, 0, 10).await.unwrap().len(), 1);
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn group_commit_failure_rolls_back_every_operation() {
        let dir = tempfile::tempdir().unwrap();
        let (store, meta, path) = start(&dir);

        // A trigger that aborts the second event makes the whole transaction
        // fail after the first operation has written its rows. The store must
        // roll the batch back and report every accepted operation as failed.
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TRIGGER fail_second BEFORE INSERT ON events
                 WHEN NEW.seq = 2
                 BEGIN SELECT RAISE(ABORT, 'injected batch failure'); END;",
            )
            .unwrap();
        }
        let outcomes = store
            .commit_batch(vec![
                request(create_file(1, "/a"), None),
                request(create_file(2, "/b"), None),
            ])
            .await;
        assert!(matches!(&outcomes[0], CommitOutcome::Failed { .. }));
        assert!(matches!(&outcomes[1], CommitOutcome::Failed { .. }));

        // Nothing from the failed transaction may survive: no event, no
        // op_id, no replay frame and no sequence.
        assert_eq!(store.events(meta.epoch, 0, 10).await.unwrap().len(), 0);
        assert_eq!(store.wire(1).await.unwrap(), None);
        assert!(
            store
                .path_state("/a")
                .await
                .unwrap()
                .unwrap()
                .object
                .is_none()
        );
        assert!(
            store
                .path_state("/b")
                .await
                .unwrap()
                .unwrap()
                .object
                .is_none()
        );
        {
            let db = Db::open(&path, Role::Server).unwrap();
            assert_eq!(db.read().unwrap().meta_i64(keys::SEQ).unwrap(), 0);
        }

        // Removing the fault lets the same operations commit with the same
        // sequence numbers, proving the retry did not consume one.
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch("DROP TRIGGER fail_second").unwrap();
        }
        let outcomes = store
            .commit_batch(vec![
                request(create_file(1, "/a"), None),
                request(create_file(2, "/b"), None),
            ])
            .await;
        assert_eq!(outcomes[0], applied(1));
        assert_eq!(outcomes[1], applied(2));
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn group_commit_answers_a_committed_duplicate_and_continues() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, _) = start(&dir);
        assert_eq!(
            store.commit(request(create_file(1, "/a"), None)).await,
            applied(1)
        );
        let outcomes = store
            .commit_batch(vec![
                request(create_file(1, "/a"), None),
                request(create_file(2, "/b"), None),
            ])
            .await;
        assert_eq!(outcomes[0], CommitOutcome::Duplicate { seq: 1 });
        assert_eq!(outcomes[1], applied(2));
        store.shutdown().await.unwrap();
    }
}
