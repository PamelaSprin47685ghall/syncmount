//! Server-side SQLite writer: one blocking thread owns the database.
//!
//! # Shape
//!
//! ```text
//! StoreHandle (async) --mpsc--> store thread: Db + State mirror + replay_wire
//! ```
//!
//! The async actor never runs SQL. It sends one [`CommitRequest`] and awaits
//! one [`CommitOutcome`]. The thread is the only writer of the server database,
//! so every commit is serial and the in-memory [`State`] is never shared.
//!
//! # Commit order
//!
//! 1. Refuse a duplicate `op_id` before anything else. A retry must receive the
//!    original sequence number even when the operation would no longer plan.
//! 2. Prepare the complete file bytes for `WRITE`, `PWRITE` and `TRUNCATE`.
//! 3. Plan against the in-memory state. A rejection consumes no sequence.
//! 4. Store the original wire frame in `replay_wire` at `seq + 1`.
//! 5. Run one SQLite transaction: bump the sequence, write the rows, append the
//!    event and record the `op_id`.
//! 6. Replace the in-memory state with the planned result.
//!
//! A crash between step 4 and step 5 leaves an orphan wire row. Replay asks
//! only for sequences that have an event, so an orphan is harmless. A stale
//! row at a sequence that is written again is replaced with `INSERT OR
//! REPLACE`.
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

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};
use tokio::sync::{mpsc, oneshot};

use crate::protocol::messages::OpClass;
use crate::server::wire::{self, WireOp};
use crate::state::{self, Change, Chunk, Errno, Ino, Kind, ObjectPatch, Reject, State, Verdict};
use crate::store::sqlite::{
    self, ChunkRef, Db, EventDraft, EventRow, ObjectKind, ReadTx, Role, WriteTx, keys,
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
    /// State digest recorded by the last compaction or clean shutdown.
    pub state_hash: [u8; 32],
}

/// The result of one commit attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitOutcome {
    /// The operation was written at this sequence number.
    Applied {
        /// Assigned event sequence.
        seq: i64,
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
    Commit {
        request: Box<CommitRequest>,
        reply: oneshot::Sender<CommitOutcome>,
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
        let (reply, response) = oneshot::channel();
        if self
            .tx
            .send(StoreCmd::Commit {
                request: Box::new(request),
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
        Ok((
            Self {
                db,
                sidecar,
                state,
                meta,
            },
            meta,
        ))
    }

    /// Serve commands until shutdown or until the handle is dropped.
    fn run(mut self, mut rx: mpsc::Receiver<StoreCmd>) {
        while let Some(command) = rx.blocking_recv() {
            match command {
                StoreCmd::Commit { request, reply } => {
                    let _ = reply.send(self.commit(*request));
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

    /// Plan, persist and apply one operation.
    fn commit(&mut self, request: CommitRequest) -> CommitOutcome {
        let CommitRequest {
            session,
            op,
            content,
            wire,
            created_at,
        } = request;

        // A retry must return the original sequence even when the operation
        // would now be rejected (for example, a repeated create).
        match self.lookup_op_id(op.op_id) {
            Ok(Some(seq)) => return CommitOutcome::Duplicate { seq },
            Ok(None) => {}
            Err(message) => return CommitOutcome::Failed { message },
        }

        let content = match self.prepare_content(&op, content) {
            Ok(content) => content,
            Err(PrepareError::Reject(reject)) => return CommitOutcome::Rejected { reject },
            Err(PrepareError::Failed(message)) => return CommitOutcome::Failed { message },
        };

        let planned = match wire::to_op(&op, content.as_deref(), &self.state, session) {
            Ok(planned) => planned,
            Err(reject) => return CommitOutcome::Rejected { reject },
        };

        let (changes, draft) = match &planned {
            Some(planned_op) => match state::plan(planned_op, &self.state) {
                Verdict::Apply(changes) => {
                    let draft = wire::event_for(&op, planned_op, &self.state, session)
                        .with_created_at(created_at);
                    (changes, draft)
                }
                Verdict::Reject(reject) => return CommitOutcome::Rejected { reject },
            },
            None => (
                Vec::new(),
                EventDraft::sync_ctrl(op.op_id, 0).with_created_at(created_at),
            ),
        };

        // Build the post-commit state off to the side. The live mirror changes
        // only after SQLite accepts the transaction.
        let mut after = self.state.clone();
        after.commit(changes.clone());

        let seq = match self.meta.seq.checked_add(1) {
            Some(seq) => seq,
            None => {
                return CommitOutcome::Failed {
                    message: "event sequence overflow".to_owned(),
                };
            }
        };
        if let Err(message) = self.write_wire(seq, &wire) {
            return CommitOutcome::Failed { message };
        }

        let plan = CommitPlan {
            seq,
            op,
            created_at,
            draft,
            changes,
            after,
            content,
        };
        match self.apply(plan) {
            Ok(after) => {
                self.state = after;
                self.meta.seq = seq;
                CommitOutcome::Applied { seq }
            }
            Err(ApplyError::Duplicate(seq)) => CommitOutcome::Duplicate { seq },
            Err(ApplyError::Failed(message)) => CommitOutcome::Failed { message },
        }
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
        if let Err(message) = self.write_wire(seq, &wire) {
            return CommitOutcome::Failed { message };
        }

        let draft = EventDraft::leave(session);
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
        CommitOutcome::Applied { seq }
    }

    /// Read the server's `op_ids` row for one operation.
    fn lookup_op_id(&self, op_id: [u8; 16]) -> Result<Option<i64>, String> {
        let read = self.db.read().map_err(err_str)?;
        Ok(read.op_id(op_id).map_err(err_str)?.map(|row| row.first_seq))
    }

    /// Build the complete post-operation file bytes.
    ///
    /// `WRITE` takes the supplied bytes as the whole file. `PWRITE` reads the
    /// old file, zero-fills any gap and patches the range. `TRUNCATE` reads the
    /// old file and resizes it with zeros. Other classes need no content.
    fn prepare_content(
        &self,
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
            let mut bytes = self.read_file_bytes(&op.path, None)?;
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

        if op.class == OpClass::TRUNCATE {
            let length = op
                .length
                .ok_or_else(|| PrepareError::Failed("TRUNCATE carries no length".to_owned()))?;
            check_size(length)?;
            if length == 0 {
                return Ok(Some(Vec::new()));
            }
            let mut bytes = self.read_file_bytes(&op.path, Some(length))?;
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
    fn read_file_bytes(&self, path: &str, limit: Option<u64>) -> Result<Vec<u8>, PrepareError> {
        let ino = self
            .state
            .resolve(path.as_bytes())
            .map_err(PrepareError::Reject)?;
        let read = self
            .db
            .read()
            .map_err(|err| PrepareError::Failed(format!("read content: {err}")))?;
        let refs = read
            .object_chunks(ino_bytes(ino))
            .map_err(|err| PrepareError::Failed(format!("read object chunks: {err}")))?;

        let mut total = 0u64;
        for chunk in &refs {
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
        for chunk in &refs {
            if bytes.len() >= wanted {
                break;
            }
            let row = read
                .chunk(chunk.hash)
                .map_err(|err| PrepareError::Failed(format!("read chunk: {err}")))?
                .ok_or_else(|| {
                    PrepareError::Failed(format!("chunk {} is missing", hex::encode(chunk.hash)))
                })?;
            let data = row.data.ok_or_else(|| {
                PrepareError::Failed(format!("chunk {} has no data", hex::encode(chunk.hash)))
            })?;
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

    /// Write the replay frame before the main transaction.
    fn write_wire(&self, seq: i64, frame: &[u8]) -> Result<(), String> {
        self.sidecar
            .execute(
                "INSERT OR REPLACE INTO replay_wire (seq, frame) VALUES (?1, ?2)",
                params![seq, frame],
            )
            .map_err(|err| format!("replay_wire write: {err}"))?;
        Ok(())
    }

    /// Run the one write transaction for an accepted operation.
    fn apply(&mut self, plan: CommitPlan) -> Result<State, ApplyError> {
        let CommitPlan {
            seq,
            op,
            created_at,
            draft,
            changes,
            after,
            content,
        } = plan;
        let tx = self
            .db
            .write()
            .map_err(|err| ApplyError::Failed(format!("begin write: {err}")))?;
        let bumped = tx
            .bump_seq()
            .map_err(|err| ApplyError::Failed(format!("bump seq: {err}")))?;
        if bumped != seq {
            return Err(ApplyError::Failed(format!(
                "event sequence moved: expected {seq}, found {bumped}"
            )));
        }

        if let Some(bytes) = content.as_deref() {
            for (chunk, data) in wire::split_chunks(bytes) {
                tx.put_chunk(chunk.hash, chunk.len, Some(data.as_slice()))
                    .map_err(|err| {
                        ApplyError::Failed(format!("put chunk {}: {err}", hex::encode(chunk.hash)))
                    })?;
            }
        }

        apply_rows(&tx, &self.state, &after, &changes, seq).map_err(ApplyError::Failed)?;

        let inserted = match tx.insert_event(seq, draft) {
            Ok(inserted) => inserted,
            Err(sqlite::StoreError::DuplicateOp { existing, .. }) => {
                return Err(ApplyError::Duplicate(existing));
            }
            Err(err) => return Err(ApplyError::Failed(format!("insert event: {err}"))),
        };
        match tx.record_op_id(op.op_id, inserted.payload_hash, seq, created_at) {
            Ok(()) => {}
            Err(sqlite::StoreError::DuplicateOp { existing, .. }) => {
                return Err(ApplyError::Duplicate(existing));
            }
            Err(err) => return Err(ApplyError::Failed(format!("record op_id: {err}"))),
        }
        tx.commit()
            .map_err(|err| ApplyError::Failed(format!("commit: {err}")))?;
        Ok(after)
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
        Ok(report)
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

/// A transaction failure.
enum ApplyError {
    /// The `op_id` was already committed at this sequence.
    Duplicate(i64),
    /// The transaction rolled back.
    Failed(String),
}

/// Everything one accepted operation needs at write time.
struct CommitPlan {
    seq: i64,
    op: WireOp,
    created_at: i64,
    draft: EventDraft,
    changes: Vec<Change>,
    after: State,
    content: Option<Vec<u8>>,
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
        state_hash: read_state_hash(&read)?,
    })
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
        assert_eq!(first, CommitOutcome::Applied { seq: 1 });
        let second = store.commit(request(create_file(2, "/b"), None)).await;
        assert_eq!(second, CommitOutcome::Applied { seq: 2 });

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
                CommitOutcome::Applied { seq: 1 }
            );
            let (op, content) = write_op(2, "/f", b"abc");
            assert_eq!(
                store.commit(request(op, content)).await,
                CommitOutcome::Applied { seq: 2 }
            );
            store.shutdown().await.unwrap();
        }

        let (store, meta) = StoreHandle::start(path).unwrap();
        assert_eq!(meta.seq, 2);
        assert_eq!(meta.state_hash, store.state_hash().await.unwrap());

        let mut truncate = base(OpClass::TRUNCATE, "/f");
        truncate.op_id = ino_id(3);
        truncate.length = Some(1);
        truncate.mtime_ns = 2_000;
        assert_eq!(
            store.commit(request(truncate, None)).await,
            CommitOutcome::Applied { seq: 3 }
        );
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
            CommitOutcome::Applied { seq: 1 }
        );
        assert_eq!(
            store.commit(request(create_file(1, "/a"), None)).await,
            CommitOutcome::Duplicate { seq: 1 }
        );
        assert_eq!(
            store.commit(request(create_file(2, "/b"), None)).await,
            CommitOutcome::Applied { seq: 2 }
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
            CommitOutcome::Applied { seq: 1 }
        );
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn compact_bumps_epoch_and_clears_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, path) = start(&dir);
        assert_eq!(
            store.commit(request(create_file(1, "/f"), None)).await,
            CommitOutcome::Applied { seq: 1 }
        );
        let (op, content) = write_op(2, "/f", b"x");
        assert_eq!(
            store.commit(request(op, content)).await,
            CommitOutcome::Applied { seq: 2 }
        );

        let report = store.compact().await.unwrap();
        assert_eq!(report.epoch, 2);
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
            CommitOutcome::Applied { seq: 1 }
        );
        assert_eq!(store.wire(99).await.unwrap(), Some(vec![7u8; 4]));
        assert_eq!(store.wire(1).await.unwrap(), Some(vec![0xAA, 0xBB]));
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn pwrite_patches_the_old_content() {
        let dir = tempfile::tempdir().unwrap();
        let (store, meta, _) = start(&dir);
        assert_eq!(
            store.commit(request(create_file(1, "/f"), None)).await,
            CommitOutcome::Applied { seq: 1 }
        );
        let (op, content) = write_op(2, "/f", b"hello world");
        assert_eq!(
            store.commit(request(op, content)).await,
            CommitOutcome::Applied { seq: 2 }
        );

        let (op, patch) = pwrite_op(3, "/f", 6, b"there");
        assert_eq!(
            store.commit(request(op, patch)).await,
            CommitOutcome::Applied { seq: 3 }
        );
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
        assert_eq!(
            store.commit(request(op, patch)).await,
            CommitOutcome::Applied { seq: 4 }
        );
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
            CommitOutcome::Applied { seq: 1 }
        );
        assert_eq!(
            store.commit(request(create_file(2, "/a/f"), None)).await,
            CommitOutcome::Applied { seq: 2 }
        );
        let (op, content) = write_op(3, "/a/f", b"x");
        assert_eq!(
            store.commit(request(op, content)).await,
            CommitOutcome::Applied { seq: 3 }
        );

        let mut rename = base(OpClass::RENAME, "/a");
        rename.op_id = ino_id(4);
        rename.path2 = Some("/b".to_owned());
        rename.mtime_ns = 2_000;
        assert_eq!(
            store.commit(request(rename, None)).await,
            CommitOutcome::Applied { seq: 4 }
        );
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
            CommitOutcome::Applied { seq: 1 }
        );
        let (op, content) = write_op(2, "/f", b"ab");
        assert_eq!(
            store.commit(request(op, content)).await,
            CommitOutcome::Applied { seq: 2 }
        );

        let mut truncate = base(OpClass::TRUNCATE, "/f");
        truncate.op_id = ino_id(3);
        truncate.length = Some(5);
        truncate.mtime_ns = 2_000;
        assert_eq!(
            store.commit(request(truncate, None)).await,
            CommitOutcome::Applied { seq: 3 }
        );

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
    async fn leave_appends_an_event_and_drops_locks() {
        let dir = tempfile::tempdir().unwrap();
        let (store, meta, _) = start(&dir);
        let holder = [9u8; 16];
        let other = [8u8; 16];
        assert_eq!(
            store.commit(request(create_file(1, "/f"), None)).await,
            CommitOutcome::Applied { seq: 1 }
        );

        let mut lock = base(OpClass::FCNTL_LOCK, "/f");
        lock.op_id = ino_id(2);
        lock.lock_type = Some(1);
        lock.lock_action = Some(0);
        lock.lock_start = Some(0);
        lock.lock_len = Some(0);
        lock.mtime_ns = 1_000;
        assert_eq!(
            store.commit(request(lock, None)).await,
            CommitOutcome::Applied { seq: 2 }
        );

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

        assert_eq!(
            store.leave(holder, vec![0xCC]).await,
            CommitOutcome::Applied { seq: 3 }
        );
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
        assert_eq!(
            store.commit(retry_request).await,
            CommitOutcome::Applied { seq: 4 }
        );
        store.shutdown().await.unwrap();
    }
}
