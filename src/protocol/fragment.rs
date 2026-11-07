//! Fragmentation, reassembly, session routing and flow-control credit.
//!
//! Owner: W5 (E1). See 44 §5 and 53 W5. This module is sans-io: it never
//! opens files or sockets. A caller supplies a [`ChunkSink`] that decides
//! where reassembled bytes land (memory, spill file, store).
//!
//! Three granularities meet here (44 §5.1): a FUSE write is one `ORDERED`,
//! content-addressed blocks are 256 KiB, and transport fragments are 64 KiB
//! of plaintext per `STREAM_DATA` frame. [`CHUNK_PLAIN`] is a v1 constant,
//! never negotiated: `total_chunks` and `chunk_index` sit in the AAD, so
//! their meaning must not depend on session state.
//!
//! Invariants enforced by this module:
//!
//! - INV-10: `index < total_chunks`, and `total_chunks` is constant for one
//!   stream. [`Fragmenter`] derives it once from `total_len`;
//!   [`Reassembler::push`] rejects any other value with
//!   [`FragmentError::TotalMismatch`].
//! - INV-11: a `(session, stream)` completes at most once. After completion
//!   every further push reports [`Progress::Duplicate`], and the sink's
//!   `finish` runs exactly once.
//!
//! Duplicates are dropped by index without a second sink write. Out-of-order
//! chunks are buffered in a `BTreeMap` capped at [`MAX_REORDER_CHUNKS`] and
//! [`MAX_REORDER_BYTES`]; the sink only ever sees in-order writes at
//! `index * CHUNK_PLAIN` (44 §5.3).

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fmt;
use std::io;
use std::time::{Duration, Instant};

use crate::protocol::frame::{SessionId, StreamId};

pub use crate::protocol::MAX_CHUNKS;

/// Plaintext bytes carried by one transport fragment (44 §5.1).
///
/// Fixed in v1. Negotiating it would make `total_chunks`/`chunk_index`
/// session-dependent, and both are covered by the AAD.
pub const CHUNK_PLAIN: usize = 64 * 1024;

/// Session inactivity timeout (44 §5.3).
pub const SESSION_TTL: Duration = Duration::from_secs(60);

/// Maximum live sessions in one [`SessionTable`] (44 §5.3).
pub const MAX_SESSIONS: usize = 32;

/// Maximum streams in one session (44 §5.3).
pub const MAX_STREAMS_PER_SESSION: usize = 8;

/// Maximum out-of-order chunks buffered per stream (44 §5.3).
pub const MAX_REORDER_CHUNKS: usize = 8;

/// Maximum out-of-order bytes buffered per stream (44 §5.3).
pub const MAX_REORDER_BYTES: usize = 8 * CHUNK_PLAIN;

/// Maximum reorder bytes buffered across one [`SessionTable`] (44 §5.3).
pub const MAX_BUFFERED_BYTES: usize = 64 * 1024 * 1024;

/// Default flow-control window (44 §5.4).
pub const CREDIT_WINDOW: u32 = 8 * 1024 * 1024;

/// Largest flow-control window a peer may grant (44 §5.4).
pub const MAX_CREDIT_WINDOW: u32 = 64 * 1024 * 1024;

/// Largest byte length representable by [`MAX_CHUNKS`] fragments.
const MAX_TOTAL_LEN: u64 = MAX_CHUNKS as u64 * CHUNK_PLAIN as u64;

/// Errors raised by the fragmentation layer.
///
/// Not `Copy`: [`FragmentError::Sink`] wraps an [`io::Error`]. The protocol
/// layer maps these to `TRN_SESSION_FULL`, `TRN_QUEUE_OVERFLOW` or a stream
/// teardown; it never exposes them on the wire verbatim.
#[derive(Debug)]
pub enum FragmentError {
    /// `total_chunks` is zero or above [`MAX_CHUNKS`].
    TotalChunksOutOfRange {
        /// Offending chunk count.
        total: u32,
        /// Ceiling.
        max: u32,
    },
    /// The declared stream length exceeds the representable 64 GiB.
    TotalLenTooLarge {
        /// Offending length.
        total_len: u64,
        /// Ceiling.
        max: u64,
    },
    /// `chunk_index` is not below `total_chunks` (INV-10).
    IndexOutOfRange {
        /// Offending index.
        index: u32,
        /// Stream chunk count.
        total: u32,
    },
    /// `total_chunks` changed inside one stream (INV-10).
    TotalMismatch {
        /// Value the stream was opened with.
        expected: u32,
        /// Value carried by this frame.
        got: u32,
    },
    /// A fragment is wider than [`CHUNK_PLAIN`].
    ChunkTooLarge {
        /// Offending length.
        len: usize,
        /// Ceiling.
        max: usize,
    },
    /// A fragment length does not match its position in the stream.
    BadChunkLen {
        /// Chunk index.
        index: u32,
        /// Length carried by the frame.
        len: usize,
        /// Length required for this index.
        expected: usize,
    },
    /// The out-of-order buffer would exceed its per-stream cap (44 §5.3).
    ReorderOverflow {
        /// Bytes or chunks already buffered, depending on the cap hit.
        buffered: usize,
        /// The cap that was hit.
        cap: usize,
    },
    /// No session entry for the route key.
    UnknownSession {
        /// Session from the route prefix.
        session: SessionId,
        /// Stream from the route prefix.
        stream: StreamId,
    },
    /// The session exists but the stream does not.
    UnknownStream {
        /// Session from the route prefix.
        session: SessionId,
        /// Stream from the route prefix.
        stream: StreamId,
    },
    /// The session table is full (44 §5.3: 32 sessions).
    SessionFull {
        /// Ceiling.
        max: usize,
    },
    /// One session already carries the maximum number of streams.
    StreamFull {
        /// Ceiling.
        max: usize,
    },
    /// The table-wide reorder budget is exhausted (44 §5.3: 64 MiB).
    BufferFull {
        /// Bytes buffered after the push.
        buffered: usize,
        /// Ceiling.
        cap: usize,
    },
    /// The caller's [`ChunkSink`] failed.
    Sink(io::Error),
    /// The sink already failed and the stream is unusable.
    SinkClosed,
    /// A table invariant was violated (for example reopening a completed key).
    Internal,
}

impl fmt::Display for FragmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TotalChunksOutOfRange { total, max } => {
                write!(f, "total chunks {total} outside 1..={max}")
            }
            Self::TotalLenTooLarge { total_len, max } => {
                write!(f, "total length {total_len} exceeds {max}")
            }
            Self::IndexOutOfRange { index, total } => {
                write!(f, "chunk index {index} outside total {total}")
            }
            Self::TotalMismatch { expected, got } => {
                write!(f, "total chunks mismatch: expected {expected}, got {got}")
            }
            Self::ChunkTooLarge { len, max } => {
                write!(f, "chunk of {len} bytes exceeds {max}")
            }
            Self::BadChunkLen {
                index,
                len,
                expected,
            } => write!(f, "chunk {index} has {len} bytes, expected {expected}"),
            Self::ReorderOverflow { buffered, cap } => {
                write!(f, "reorder buffer at {buffered} exceeds cap {cap}")
            }
            Self::UnknownSession { session, stream } => {
                write!(f, "unknown session {session} stream {stream:?}")
            }
            Self::UnknownStream { session, stream } => {
                write!(f, "unknown stream {stream:?} in session {session}")
            }
            Self::SessionFull { max } => write!(f, "session table full (max {max})"),
            Self::StreamFull { max } => write!(f, "session stream table full (max {max})"),
            Self::BufferFull { buffered, cap } => {
                write!(
                    f,
                    "reorder buffer {buffered} bytes exceeds global cap {cap}"
                )
            }
            Self::Sink(err) => write!(f, "chunk sink failed: {err}"),
            Self::SinkClosed => write!(f, "chunk sink already closed"),
            Self::Internal => write!(f, "fragment layer internal invariant violated"),
        }
    }
}

impl Error for FragmentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sink(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for FragmentError {
    fn from(err: io::Error) -> Self {
        Self::Sink(err)
    }
}

/// Route key of one reassembly stream: `(session_id, stream)` (44 §5.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct FragmentKey {
    /// Session from the route prefix.
    pub session: SessionId,
    /// Stream from the route prefix.
    pub stream: StreamId,
}

impl FragmentKey {
    /// Build a route key.
    pub const fn new(session: SessionId, stream: StreamId) -> Self {
        Self { session, stream }
    }
}

/// Sender-side fragmenter for one stream.
///
/// `total_chunks` is derived once from `total_len` and never changes
/// (INV-10). A zero-length stream still has one zero-length chunk, so the
/// route prefix always carries `total_chunks >= 1`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fragmenter {
    session: SessionId,
    stream: StreamId,
    total: u32,
    total_len: u64,
}

impl Fragmenter {
    /// Plan a stream of `total_len` bytes.
    ///
    /// `total_chunks = max(1, ceil(total_len / CHUNK_PLAIN))`; the protocol
    /// ceiling is [`MAX_CHUNKS`] (64 GiB).
    pub fn new(
        session: SessionId,
        stream: StreamId,
        total_len: u64,
    ) -> Result<Self, FragmentError> {
        if total_len > MAX_TOTAL_LEN {
            return Err(FragmentError::TotalLenTooLarge {
                total_len,
                max: MAX_TOTAL_LEN,
            });
        }
        let chunks = total_len.div_ceil(CHUNK_PLAIN as u64).max(1);
        let total = match u32::try_from(chunks) {
            Ok(total) if total <= MAX_CHUNKS => total,
            Ok(total) => {
                return Err(FragmentError::TotalChunksOutOfRange {
                    total,
                    max: MAX_CHUNKS,
                });
            }
            Err(_) => {
                return Err(FragmentError::TotalChunksOutOfRange {
                    total: u32::MAX,
                    max: MAX_CHUNKS,
                });
            }
        };
        Ok(Self {
            session,
            stream,
            total,
            total_len,
        })
    }

    /// Number of fragments; always at least one.
    pub const fn total_chunks(&self) -> u32 {
        self.total
    }

    /// Declared stream length in bytes.
    pub const fn total_len(&self) -> u64 {
        self.total_len
    }

    /// Session this stream belongs to.
    pub const fn session(&self) -> SessionId {
        self.session
    }

    /// Stream number inside the session.
    pub const fn stream(&self) -> StreamId {
        self.stream
    }

    /// Exact plaintext length of fragment `index` (INV-10).
    ///
    /// Every non-final chunk is [`CHUNK_PLAIN`]; the final chunk carries the
    /// remainder, which is zero for an empty stream.
    pub fn chunk_len(&self, index: u32) -> Result<usize, FragmentError> {
        if index >= self.total {
            return Err(FragmentError::IndexOutOfRange {
                index,
                total: self.total,
            });
        }
        if index + 1 < self.total {
            return Ok(CHUNK_PLAIN);
        }
        let consumed = u64::from(index) * CHUNK_PLAIN as u64;
        Ok((self.total_len - consumed) as usize)
    }

    /// Wrap the plaintext of fragment `index`.
    ///
    /// Enforces INV-10: `index < total`, non-final chunks exactly
    /// [`CHUNK_PLAIN`], the final chunk at most [`CHUNK_PLAIN`].
    pub fn fragment<'a>(
        &self,
        index: u32,
        plaintext: &'a [u8],
    ) -> Result<Fragment<'a>, FragmentError> {
        if index >= self.total {
            return Err(FragmentError::IndexOutOfRange {
                index,
                total: self.total,
            });
        }
        if plaintext.len() > CHUNK_PLAIN {
            return Err(FragmentError::ChunkTooLarge {
                len: plaintext.len(),
                max: CHUNK_PLAIN,
            });
        }
        let expected = self.chunk_len(index)?;
        if plaintext.len() != expected {
            return Err(FragmentError::BadChunkLen {
                index,
                len: plaintext.len(),
                expected,
            });
        }
        Ok(Fragment {
            index,
            total: self.total,
            plaintext,
        })
    }
}

/// One planned fragment. `plaintext` borrows the caller's buffer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fragment<'a> {
    /// Zero-based fragment index.
    pub index: u32,
    /// Stream chunk count; constant for the stream (INV-10).
    pub total: u32,
    /// Fragment bytes; length already validated against [`CHUNK_PLAIN`].
    pub plaintext: &'a [u8],
}

impl Fragment<'_> {
    /// In-stream offset: `index * CHUNK_PLAIN` (44 §5.3).
    ///
    /// This is a stream offset, not a file offset. The op layer adds its own
    /// base offset inside its sink.
    pub const fn offset(&self) -> u64 {
        self.index as u64 * CHUNK_PLAIN as u64
    }
}

/// Result of feeding one fragment to a [`Reassembler`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Progress {
    /// Fragment accepted; the stream is still incomplete.
    Accepted,
    /// Fragment index was already seen (or the stream already completed).
    Duplicate,
    /// This fragment completed the stream; the sink was finalized.
    Complete,
}

/// Destination for reassembled bytes.
///
/// `write_at` always receives strictly increasing, contiguous offsets that
/// start at zero, so an implementation may append. `finish` is called
/// exactly once, on the fragment that completes the stream.
pub trait ChunkSink {
    /// Write `data` at in-stream offset `offset`.
    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()>;

    /// Finalize the stream. Consumes the sink.
    fn finish(self: Box<Self>) -> io::Result<()>;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ReassemblyState {
    Open,
    Complete,
    Closed,
}

/// Receiver-side reassembly for one stream.
///
/// Duplicates are detected with a `u64` bitset (not `Vec<bool>`). Out-of-order
/// chunks wait in a `BTreeMap` capped at [`MAX_REORDER_CHUNKS`] chunks and
/// [`MAX_REORDER_BYTES`] bytes; in-order chunks are written immediately
/// (44 §5.3).
pub struct Reassembler {
    total: u32,
    received: Vec<u64>,
    received_count: u32,
    next: u32,
    reorder: BTreeMap<u32, Vec<u8>>,
    reorder_bytes: usize,
    bytes_written: u64,
    sink: Option<Box<dyn ChunkSink>>,
    state: ReassemblyState,
}

impl Reassembler {
    /// Create a reassembler for `total_chunks` fragments.
    ///
    /// `total_chunks` must be in `1..=MAX_CHUNKS` (INV-10).
    pub fn new(total_chunks: u32, sink: Box<dyn ChunkSink>) -> Result<Self, FragmentError> {
        validate_total_chunks(total_chunks)?;
        let words = total_chunks.div_ceil(64) as usize;
        Ok(Self {
            total: total_chunks,
            received: vec![0; words],
            received_count: 0,
            next: 0,
            reorder: BTreeMap::new(),
            reorder_bytes: 0,
            bytes_written: 0,
            sink: Some(sink),
            state: ReassemblyState::Open,
        })
    }

    /// Feed one fragment.
    ///
    /// Order of checks: completion state (INV-11), `total_chunks` stability
    /// (INV-10), index bounds (INV-10), fragment width, duplicate index.
    /// After a sink failure the stream is closed and further pushes return
    /// [`FragmentError::SinkClosed`].
    pub fn push(
        &mut self,
        index: u32,
        total_chunks: u32,
        data: &[u8],
    ) -> Result<Progress, FragmentError> {
        if self.state == ReassemblyState::Complete {
            return Ok(Progress::Duplicate);
        }
        if self.state == ReassemblyState::Closed {
            return Err(FragmentError::SinkClosed);
        }
        if total_chunks != self.total {
            return Err(FragmentError::TotalMismatch {
                expected: self.total,
                got: total_chunks,
            });
        }
        if index >= self.total {
            return Err(FragmentError::IndexOutOfRange {
                index,
                total: self.total,
            });
        }
        if data.len() > CHUNK_PLAIN {
            return Err(FragmentError::ChunkTooLarge {
                len: data.len(),
                max: CHUNK_PLAIN,
            });
        }
        if index + 1 < self.total && data.len() != CHUNK_PLAIN {
            return Err(FragmentError::BadChunkLen {
                index,
                len: data.len(),
                expected: CHUNK_PLAIN,
            });
        }
        if self.is_received(index) {
            return Ok(Progress::Duplicate);
        }
        if index == self.next {
            self.write_in_order(index, data)?;
            self.next += 1;
            self.drain()?;
            if self.received_count == self.total {
                return self.finish();
            }
            return Ok(Progress::Accepted);
        }
        if self.reorder.len() >= MAX_REORDER_CHUNKS {
            return Err(FragmentError::ReorderOverflow {
                buffered: self.reorder.len(),
                cap: MAX_REORDER_CHUNKS,
            });
        }
        let buffered = self.reorder_bytes + data.len();
        if buffered > MAX_REORDER_BYTES {
            return Err(FragmentError::ReorderOverflow {
                buffered,
                cap: MAX_REORDER_BYTES,
            });
        }
        self.set_received(index);
        self.received_count += 1;
        self.reorder_bytes = buffered;
        self.reorder.insert(index, data.to_vec());
        Ok(Progress::Accepted)
    }

    /// Whether the sink was finalized successfully (INV-11).
    pub const fn is_complete(&self) -> bool {
        matches!(self.state, ReassemblyState::Complete)
    }

    /// Stream chunk count, constant for the stream's lifetime (INV-10).
    pub const fn total_chunks(&self) -> u32 {
        self.total
    }

    /// Number of distinct chunks received so far.
    pub const fn received_chunks(&self) -> u32 {
        self.received_count
    }

    /// Indices not yet received, in ascending order.
    pub fn missing(&self) -> Vec<u32> {
        (0..self.total)
            .filter(|&index| !self.is_received(index))
            .collect()
    }

    /// Chunks waiting in the out-of-order buffer.
    pub fn buffered_chunks(&self) -> usize {
        self.reorder.len()
    }

    /// Bytes waiting in the out-of-order buffer.
    pub const fn buffered_bytes(&self) -> usize {
        self.reorder_bytes
    }

    /// Bytes handed to the sink, including zero-length chunks.
    pub const fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    fn is_received(&self, index: u32) -> bool {
        let word = (index / 64) as usize;
        let bit = index % 64;
        self.received[word] & (1u64 << bit) != 0
    }

    fn set_received(&mut self, index: u32) {
        let word = (index / 64) as usize;
        let bit = index % 64;
        self.received[word] |= 1u64 << bit;
    }

    fn write_in_order(&mut self, index: u32, data: &[u8]) -> Result<(), FragmentError> {
        let offset = u64::from(index) * CHUNK_PLAIN as u64;
        let result = match self.sink.as_mut() {
            Some(sink) => sink.write_at(offset, data),
            None => return Err(FragmentError::SinkClosed),
        };
        if let Err(err) = result {
            self.sink = None;
            self.state = ReassemblyState::Closed;
            return Err(FragmentError::Sink(err));
        }
        self.set_received(index);
        self.received_count += 1;
        self.bytes_written += data.len() as u64;
        Ok(())
    }

    fn drain(&mut self) -> Result<(), FragmentError> {
        while let Some(data) = self.reorder.remove(&self.next) {
            self.reorder_bytes -= data.len();
            let offset = u64::from(self.next) * CHUNK_PLAIN as u64;
            let result = match self.sink.as_mut() {
                Some(sink) => sink.write_at(offset, &data),
                None => return Err(FragmentError::SinkClosed),
            };
            if let Err(err) = result {
                self.sink = None;
                self.state = ReassemblyState::Closed;
                return Err(FragmentError::Sink(err));
            }
            self.bytes_written += data.len() as u64;
            self.next += 1;
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<Progress, FragmentError> {
        let Some(sink) = self.sink.take() else {
            self.state = ReassemblyState::Closed;
            return Err(FragmentError::SinkClosed);
        };
        match sink.finish() {
            Ok(()) => {
                self.state = ReassemblyState::Complete;
                Ok(Progress::Complete)
            }
            Err(err) => {
                self.state = ReassemblyState::Closed;
                Err(FragmentError::Sink(err))
            }
        }
    }
}

impl fmt::Debug for Reassembler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reassembler")
            .field("total", &self.total)
            .field("next", &self.next)
            .field("received", &self.received_count)
            .field("buffered_chunks", &self.reorder.len())
            .field("buffered_bytes", &self.reorder_bytes)
            .field("bytes_written", &self.bytes_written)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

fn validate_total_chunks(total: u32) -> Result<(), FragmentError> {
    if total == 0 || total > MAX_CHUNKS {
        return Err(FragmentError::TotalChunksOutOfRange {
            total,
            max: MAX_CHUNKS,
        });
    }
    Ok(())
}

struct SessionEntry {
    last_seen: Instant,
    streams: HashMap<StreamId, Reassembler>,
}

impl SessionEntry {
    fn new(now: Instant) -> Self {
        Self {
            last_seen: now,
            streams: HashMap::new(),
        }
    }
}

/// Routing table for live reassembly streams, keyed by
/// `(session_id, stream)` (44 §5.3).
///
/// Caps: [`MAX_SESSIONS`] sessions, [`MAX_STREAMS_PER_SESSION`] streams per
/// session, [`MAX_BUFFERED_BYTES`] of out-of-order bytes table-wide. A
/// `TotalMismatch` invalidates the whole session; any other push error
/// invalidates only that stream. Completed keys stay in a dedup set until
/// `close` or `sweep`, so a late duplicate still reports
/// [`Progress::Duplicate`] (INV-11).
pub struct SessionTable {
    max_sessions: usize,
    max_streams: usize,
    max_buffered: usize,
    ttl: Duration,
    sessions: HashMap<SessionId, SessionEntry>,
    completed: HashMap<FragmentKey, Instant>,
    buffered_bytes: usize,
}

impl SessionTable {
    /// Table with the protocol defaults from 44 §5.3.
    pub fn new() -> Self {
        Self::with_limits(
            MAX_SESSIONS,
            MAX_STREAMS_PER_SESSION,
            MAX_BUFFERED_BYTES,
            SESSION_TTL,
        )
    }

    /// Table with explicit limits. Used by tests and by callers that need a
    /// smaller footprint than the protocol ceiling.
    pub fn with_limits(
        max_sessions: usize,
        max_streams: usize,
        max_buffered: usize,
        ttl: Duration,
    ) -> Self {
        Self {
            max_sessions,
            max_streams,
            max_buffered,
            ttl,
            sessions: HashMap::new(),
            completed: HashMap::new(),
            buffered_bytes: 0,
        }
    }

    /// Open a stream, creating the session when needed.
    ///
    /// Idempotent for the same key and `total_chunks`: the existing
    /// reassembler is returned and the supplied sink is dropped. A different
    /// `total_chunks` is [`FragmentError::TotalMismatch`] (INV-10). Reopening
    /// a completed key is [`FragmentError::Internal`]; call [`Self::close`]
    /// first to start over.
    pub fn open(
        &mut self,
        key: FragmentKey,
        total: u32,
        sink: Box<dyn ChunkSink>,
        now: Instant,
    ) -> Result<&mut Reassembler, FragmentError> {
        validate_total_chunks(total)?;
        if self.completed.contains_key(&key) {
            return Err(FragmentError::Internal);
        }
        let session_count = self.sessions.len();
        let entry = match self.sessions.entry(key.session) {
            Entry::Occupied(occupied) => occupied.into_mut(),
            Entry::Vacant(vacant) => {
                if session_count >= self.max_sessions {
                    return Err(FragmentError::SessionFull {
                        max: self.max_sessions,
                    });
                }
                vacant.insert(SessionEntry::new(now))
            }
        };
        entry.last_seen = now;
        let stream_count = entry.streams.len();
        match entry.streams.entry(key.stream) {
            Entry::Occupied(occupied) => {
                let reassembler = occupied.into_mut();
                let existing = reassembler.total_chunks();
                if existing != total {
                    return Err(FragmentError::TotalMismatch {
                        expected: existing,
                        got: total,
                    });
                }
                Ok(reassembler)
            }
            Entry::Vacant(vacant) => {
                if stream_count >= self.max_streams {
                    return Err(FragmentError::StreamFull {
                        max: self.max_streams,
                    });
                }
                Ok(vacant.insert(Reassembler::new(total, sink)?))
            }
        }
    }

    /// Feed one fragment to the stream named by `key`.
    ///
    /// Refreshes the session deadline. A `TotalMismatch` discards the whole
    /// session (44 §5.3); any other push error discards the stream. If the
    /// table-wide reorder budget is exceeded, the session is discarded and
    /// [`FragmentError::BufferFull`] is returned.
    pub fn push(
        &mut self,
        key: FragmentKey,
        index: u32,
        total: u32,
        data: &[u8],
        now: Instant,
    ) -> Result<Progress, FragmentError> {
        if let Some(seen) = self.completed.get_mut(&key) {
            *seen = now;
            return Ok(Progress::Duplicate);
        }
        let Some(entry) = self.sessions.get_mut(&key.session) else {
            return Err(FragmentError::UnknownSession {
                session: key.session,
                stream: key.stream,
            });
        };
        entry.last_seen = now;
        let Some(reassembler) = entry.streams.get_mut(&key.stream) else {
            return Err(FragmentError::UnknownStream {
                session: key.session,
                stream: key.stream,
            });
        };
        let before = reassembler.buffered_bytes();
        let result = reassembler.push(index, total, data);
        let after = reassembler.buffered_bytes();
        self.buffered_bytes = self
            .buffered_bytes
            .saturating_sub(before)
            .saturating_add(after);
        match result {
            Ok(Progress::Complete) => {
                self.remove_stream(key.session, key.stream);
                self.completed.insert(key, now);
                Ok(Progress::Complete)
            }
            Ok(progress) => {
                if self.buffered_bytes > self.max_buffered {
                    let buffered = self.buffered_bytes;
                    self.discard_session(key.session);
                    return Err(FragmentError::BufferFull {
                        buffered,
                        cap: self.max_buffered,
                    });
                }
                Ok(progress)
            }
            Err(FragmentError::TotalMismatch { expected, got }) => {
                self.discard_session(key.session);
                Err(FragmentError::TotalMismatch { expected, got })
            }
            Err(err) => {
                self.remove_stream(key.session, key.stream);
                Err(err)
            }
        }
    }

    /// Forget one key, including its completed marker.
    pub fn close(&mut self, key: FragmentKey) {
        self.completed.remove(&key);
        self.remove_stream(key.session, key.stream);
    }

    /// Drop sessions and completed keys idle for at least the TTL.
    ///
    /// Returns every key that was released, sorted. An expired session
    /// releases all its stream keys; a completed key expires on its own
    /// deadline (refreshed by duplicate pushes).
    pub fn sweep(&mut self, now: Instant) -> Vec<FragmentKey> {
        let mut expired_sessions = Vec::new();
        for (session, entry) in self.sessions.iter() {
            if now.saturating_duration_since(entry.last_seen) >= self.ttl {
                expired_sessions.push(*session);
            }
        }
        let mut expired = Vec::new();
        for session in expired_sessions {
            if let Some(entry) = self.sessions.remove(&session) {
                for (stream, reassembler) in entry.streams.iter() {
                    self.buffered_bytes = self
                        .buffered_bytes
                        .saturating_sub(reassembler.buffered_bytes());
                    expired.push(FragmentKey::new(session, *stream));
                }
            }
        }
        let mut expired_completed = Vec::new();
        for (key, seen) in self.completed.iter() {
            if now.saturating_duration_since(*seen) >= self.ttl {
                expired_completed.push(*key);
            }
        }
        for key in expired_completed {
            self.completed.remove(&key);
            expired.push(key);
        }
        expired.sort_unstable();
        expired
    }

    /// Live sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Live streams across all sessions.
    pub fn stream_count(&self) -> usize {
        self.sessions
            .values()
            .map(|entry| entry.streams.len())
            .sum()
    }

    /// Out-of-order bytes held by the table.
    pub const fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    /// Whether the key completed and has not been closed or swept.
    pub fn is_completed(&self, key: FragmentKey) -> bool {
        self.completed.contains_key(&key)
    }

    fn remove_stream(&mut self, session: SessionId, stream: StreamId) {
        let Some(entry) = self.sessions.get_mut(&session) else {
            return;
        };
        if let Some(reassembler) = entry.streams.remove(&stream) {
            self.buffered_bytes = self
                .buffered_bytes
                .saturating_sub(reassembler.buffered_bytes());
        }
        let empty = entry.streams.is_empty();
        if empty {
            self.sessions.remove(&session);
        }
    }

    fn discard_session(&mut self, session: SessionId) {
        if let Some(entry) = self.sessions.remove(&session) {
            for reassembler in entry.streams.values() {
                self.buffered_bytes = self
                    .buffered_bytes
                    .saturating_sub(reassembler.buffered_bytes());
            }
        }
        self.completed.retain(|key, _| key.session != session);
    }
}

impl Default for SessionTable {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SessionTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionTable")
            .field("sessions", &self.sessions.len())
            .field("streams", &self.stream_count())
            .field("buffered_bytes", &self.buffered_bytes)
            .field("completed", &self.completed.len())
            .finish_non_exhaustive()
    }
}

/// Per-stream flow-control credit (44 §5.4).
///
/// `granted` is the window the peer allows, `in_flight` the bytes reserved
/// by the sender. A FLOW message adds to `granted`, clamped at `cap`.
/// This is not the broadcast history window, which is always zero.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Credit {
    granted: u32,
    in_flight: u32,
    cap: u32,
}

impl Credit {
    /// Window of `bytes`, capped at [`MAX_CREDIT_WINDOW`].
    pub const fn new(bytes: u32) -> Self {
        Self::with_cap(bytes, MAX_CREDIT_WINDOW)
    }

    /// Window of `bytes` with an explicit cap, itself capped at
    /// [`MAX_CREDIT_WINDOW`]. A grant above the cap is clamped.
    pub const fn with_cap(bytes: u32, cap: u32) -> Self {
        let cap = if cap < MAX_CREDIT_WINDOW {
            cap
        } else {
            MAX_CREDIT_WINDOW
        };
        let granted = if bytes < cap { bytes } else { cap };
        Self {
            granted,
            in_flight: 0,
            cap,
        }
    }

    /// Reserve `n` bytes. Returns `false` when the window would be exceeded
    /// or the counter would overflow (checked add).
    pub fn try_take(&mut self, n: u32) -> bool {
        let Some(next) = self.in_flight.checked_add(n) else {
            return false;
        };
        if next > self.granted {
            return false;
        }
        self.in_flight = next;
        true
    }

    /// Add `n` bytes of credit, clamped at the cap. Returns the bytes that
    /// actually became available.
    pub fn grant(&mut self, n: u32) -> u32 {
        let room = self.cap.saturating_sub(self.granted);
        let added = if n < room { n } else { room };
        self.granted = self.granted.saturating_add(added);
        added
    }

    /// Release `n` in-flight bytes. Returns the bytes actually released.
    pub fn release(&mut self, n: u32) -> u32 {
        let released = if n < self.in_flight {
            n
        } else {
            self.in_flight
        };
        self.in_flight -= released;
        released
    }

    /// Bytes the sender may still take.
    pub const fn available(&self) -> u32 {
        self.granted.saturating_sub(self.in_flight)
    }

    /// Bytes currently reserved.
    pub const fn in_flight(&self) -> u32 {
        self.in_flight
    }

    /// Total window the peer granted.
    pub const fn granted(&self) -> u32 {
        self.granted
    }

    /// Hard ceiling of this window.
    pub const fn cap(&self) -> u32 {
        self.cap
    }

    /// Start a fresh window of `bytes` (clamped at the cap) with nothing in
    /// flight.
    pub fn reset(&mut self, bytes: u32) {
        self.granted = if bytes < self.cap { bytes } else { self.cap };
        self.in_flight = 0;
    }
}

impl Default for Credit {
    fn default() -> Self {
        Self::new(CREDIT_WINDOW)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use proptest::prelude::*;

    use super::*;

    struct RecordingSink {
        probe: SinkProbe,
        fail_write: bool,
        fail_finish: bool,
    }

    impl ChunkSink for RecordingSink {
        fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
            if self.fail_write {
                return Err(io::Error::other("synthetic write failure"));
            }
            let mut buf = self.probe.buf.borrow_mut();
            assert_eq!(
                offset as usize,
                buf.len(),
                "sink writes must be in stream order"
            );
            buf.extend_from_slice(data);
            self.probe.writes.set(self.probe.writes.get() + 1);
            Ok(())
        }

        fn finish(self: Box<Self>) -> io::Result<()> {
            self.probe.finishes.set(self.probe.finishes.get() + 1);
            if self.fail_finish {
                Err(io::Error::other("synthetic finish failure"))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Clone, Default)]
    struct SinkProbe {
        buf: Rc<RefCell<Vec<u8>>>,
        writes: Rc<Cell<usize>>,
        finishes: Rc<Cell<usize>>,
    }

    impl SinkProbe {
        fn new() -> Self {
            Self::default()
        }

        fn sink(&self) -> Box<dyn ChunkSink> {
            Box::new(RecordingSink {
                probe: self.clone(),
                fail_write: false,
                fail_finish: false,
            })
        }

        fn failing_write(&self) -> Box<dyn ChunkSink> {
            Box::new(RecordingSink {
                probe: self.clone(),
                fail_write: true,
                fail_finish: false,
            })
        }

        fn failing_finish(&self) -> Box<dyn ChunkSink> {
            Box::new(RecordingSink {
                probe: self.clone(),
                fail_write: false,
                fail_finish: true,
            })
        }

        fn bytes(&self) -> Vec<u8> {
            self.buf.borrow().clone()
        }

        fn writes(&self) -> usize {
            self.writes.get()
        }

        fn finishes(&self) -> usize {
            self.finishes.get()
        }
    }

    fn payload(total_len: u64) -> Vec<u8> {
        (0..total_len as usize)
            .map(|index| (index % 251) as u8)
            .collect()
    }

    fn chunk_bytes(fragmenter: &Fragmenter, payload: &[u8]) -> Vec<Vec<u8>> {
        (0..fragmenter.total_chunks())
            .map(|index| {
                let len = fragmenter.chunk_len(index).unwrap();
                let start = index as usize * CHUNK_PLAIN;
                payload[start..start + len].to_vec()
            })
            .collect()
    }

    fn key(session: u128, stream: u8) -> FragmentKey {
        FragmentKey::new(SessionId(session), StreamId(stream))
    }

    fn permutations(items: usize) -> Vec<Vec<u32>> {
        fn heap(k: usize, items: &mut [u32], out: &mut Vec<Vec<u32>>) {
            if k == 1 {
                out.push(items.to_vec());
                return;
            }
            for index in 0..k - 1 {
                heap(k - 1, items, out);
                if k % 2 == 0 {
                    items.swap(index, k - 1);
                } else {
                    items.swap(0, k - 1);
                }
            }
            heap(k - 1, items, out);
        }
        let mut items: Vec<u32> = (0..items as u32).collect();
        let mut out = Vec::new();
        heap(items.len(), &mut items, &mut out);
        out
    }

    /// 44:V5 chunk count boundaries and the 64 GiB ceiling.
    #[test]
    fn u_fragment_chunk_count() {
        let session = SessionId(0x11);
        let stream = StreamId::BLOCK;

        let empty = Fragmenter::new(session, stream, 0).unwrap();
        assert_eq!(empty.total_chunks(), 1);
        assert_eq!(empty.total_len(), 0);
        assert_eq!(empty.session(), session);
        assert_eq!(empty.stream(), stream);
        assert_eq!(empty.chunk_len(0).unwrap(), 0);

        assert_eq!(
            Fragmenter::new(session, stream, 1).unwrap().total_chunks(),
            1
        );
        assert_eq!(
            Fragmenter::new(session, stream, CHUNK_PLAIN as u64)
                .unwrap()
                .total_chunks(),
            1
        );
        assert_eq!(
            Fragmenter::new(session, stream, CHUNK_PLAIN as u64 + 1)
                .unwrap()
                .total_chunks(),
            2
        );
        assert_eq!(
            Fragmenter::new(session, stream, 5 * CHUNK_PLAIN as u64)
                .unwrap()
                .total_chunks(),
            5
        );

        let max_len = MAX_CHUNKS as u64 * CHUNK_PLAIN as u64;
        let max = Fragmenter::new(session, stream, max_len).unwrap();
        assert_eq!(max.total_chunks(), MAX_CHUNKS);
        assert_eq!(max.total_len(), max_len);

        assert!(matches!(
            Fragmenter::new(session, stream, max_len + 1),
            Err(FragmentError::TotalLenTooLarge { total_len, max: ceiling })
                if total_len == max_len + 1 && ceiling == max_len
        ));
        assert!(matches!(
            Fragmenter::new(session, stream, u64::MAX),
            Err(FragmentError::TotalLenTooLarge { .. })
        ));
    }

    /// 44:V5 fragment bounds: index, width, final chunk and empty stream.
    #[test]
    fn u_fragment_fragment_bounds() {
        let session = SessionId(0x22);
        let stream = StreamId::OP_DATA;
        let total_len = 2 * CHUNK_PLAIN as u64 + 10;
        let fragmenter = Fragmenter::new(session, stream, total_len).unwrap();
        assert_eq!(fragmenter.total_chunks(), 3);
        assert_eq!(fragmenter.chunk_len(0).unwrap(), CHUNK_PLAIN);
        assert_eq!(fragmenter.chunk_len(1).unwrap(), CHUNK_PLAIN);
        assert_eq!(fragmenter.chunk_len(2).unwrap(), 10);

        assert!(matches!(
            fragmenter.chunk_len(3),
            Err(FragmentError::IndexOutOfRange { index: 3, total: 3 })
        ));
        assert!(matches!(
            fragmenter.fragment(3, &[]),
            Err(FragmentError::IndexOutOfRange { index: 3, total: 3 })
        ));

        let oversized = vec![0u8; CHUNK_PLAIN + 1];
        assert!(matches!(
            fragmenter.fragment(0, &oversized),
            Err(FragmentError::ChunkTooLarge { len, max })
                if len == CHUNK_PLAIN + 1 && max == CHUNK_PLAIN
        ));

        let short_middle = vec![0u8; CHUNK_PLAIN - 1];
        assert!(matches!(
            fragmenter.fragment(0, &short_middle),
            Err(FragmentError::BadChunkLen { index: 0, len, expected })
                if len == CHUNK_PLAIN - 1 && expected == CHUNK_PLAIN
        ));

        let full = vec![0u8; CHUNK_PLAIN];
        let first = fragmenter.fragment(0, &full).unwrap();
        assert_eq!(first.index, 0);
        assert_eq!(first.total, 3);
        assert_eq!(first.plaintext, &full[..]);
        assert_eq!(first.offset(), 0);
        assert_eq!(
            fragmenter.fragment(1, &full).unwrap().offset(),
            CHUNK_PLAIN as u64
        );

        let short_final = vec![0u8; 9];
        assert!(matches!(
            fragmenter.fragment(2, &short_final),
            Err(FragmentError::BadChunkLen {
                index: 2,
                len: 9,
                expected: 10
            })
        ));
        let final_chunk = vec![0u8; 10];
        assert_eq!(
            fragmenter.fragment(2, &final_chunk).unwrap().offset(),
            2 * CHUNK_PLAIN as u64
        );

        let zero = Fragmenter::new(session, stream, 0).unwrap();
        assert_eq!(zero.chunk_len(0).unwrap(), 0);
        let empty = zero.fragment(0, &[]).unwrap();
        assert_eq!(empty.offset(), 0);
        assert!(empty.plaintext.is_empty());
        assert!(matches!(
            zero.fragment(0, &[0u8; 1]),
            Err(FragmentError::BadChunkLen {
                index: 0,
                len: 1,
                expected: 0
            })
        ));
    }

    /// 44:V5 all 120 delivery orders of five chunks reassemble exactly once.
    #[test]
    fn u_fragment_reassembly_all_permutations() {
        let total_len = 4 * CHUNK_PLAIN as u64 + 777;
        let fragmenter = Fragmenter::new(SessionId(0x33), StreamId::BLOCK, total_len).unwrap();
        let total = fragmenter.total_chunks();
        assert_eq!(total, 5);
        let payload = payload(total_len);
        let chunks = chunk_bytes(&fragmenter, &payload);

        let orders = permutations(total as usize);
        assert_eq!(orders.len(), 120);
        let unique: std::collections::BTreeSet<_> = orders.iter().collect();
        assert_eq!(unique.len(), 120);

        for order in orders {
            let probe = SinkProbe::new();
            let mut reassembler = Reassembler::new(total, probe.sink()).unwrap();
            let mut completes = 0;
            for (position, &index) in order.iter().enumerate() {
                let progress = reassembler
                    .push(index, total, &chunks[index as usize])
                    .unwrap();
                if progress == Progress::Complete {
                    completes += 1;
                    assert_eq!(position, order.len() - 1, "only the last chunk completes");
                } else {
                    assert_eq!(progress, Progress::Accepted);
                }
            }
            assert_eq!(completes, 1);
            assert!(reassembler.is_complete());
            assert_eq!(reassembler.received_chunks(), total);
            assert!(reassembler.missing().is_empty());
            assert_eq!(reassembler.buffered_chunks(), 0);
            assert_eq!(reassembler.buffered_bytes(), 0);
            assert_eq!(reassembler.bytes_written(), total_len);
            assert_eq!(probe.bytes(), payload);
            assert_eq!(probe.finishes(), 1);

            assert_eq!(
                reassembler
                    .push(order[0], total, &chunks[order[0] as usize])
                    .unwrap(),
                Progress::Duplicate
            );
            assert_eq!(probe.finishes(), 1);
        }
    }

    /// 44:V5 duplicates are dropped without a second sink write (INV-11).
    #[test]
    fn u_fragment_reassembly_duplicates() {
        let total_len = 3 * CHUNK_PLAIN as u64 + 5;
        let fragmenter = Fragmenter::new(SessionId(0x44), StreamId::BLOCK, total_len).unwrap();
        let total = fragmenter.total_chunks();
        assert_eq!(total, 4);
        let payload = payload(total_len);
        let chunks = chunk_bytes(&fragmenter, &payload);

        let probe = SinkProbe::new();
        let mut reassembler = Reassembler::new(total, probe.sink()).unwrap();

        assert_eq!(
            reassembler.push(0, total, &chunks[0]).unwrap(),
            Progress::Accepted
        );
        assert_eq!(
            reassembler.push(0, total, &chunks[0]).unwrap(),
            Progress::Duplicate
        );
        assert_eq!(probe.writes(), 1);

        assert_eq!(
            reassembler.push(2, total, &chunks[2]).unwrap(),
            Progress::Accepted
        );
        assert_eq!(
            reassembler.push(2, total, &chunks[2]).unwrap(),
            Progress::Duplicate
        );
        assert_eq!(reassembler.buffered_chunks(), 1);

        assert_eq!(
            reassembler.push(3, total, &chunks[3]).unwrap(),
            Progress::Accepted
        );
        assert_eq!(
            reassembler.push(1, total, &chunks[1]).unwrap(),
            Progress::Complete
        );
        assert_eq!(probe.bytes(), payload);
        assert_eq!(probe.writes(), total as usize);
        assert_eq!(probe.finishes(), 1);

        for index in 0..total {
            assert_eq!(
                reassembler
                    .push(index, total, &chunks[index as usize])
                    .unwrap(),
                Progress::Duplicate
            );
        }
        assert_eq!(probe.writes(), total as usize);
        assert_eq!(probe.finishes(), 1);
    }

    /// 44:V5 a single missing chunk keeps the stream open.
    #[test]
    fn u_fragment_reassembly_missing() {
        let total_len = 3 * CHUNK_PLAIN as u64 + 9;
        let fragmenter = Fragmenter::new(SessionId(0x55), StreamId::BLOCK, total_len).unwrap();
        let total = fragmenter.total_chunks();
        let payload = payload(total_len);
        let chunks = chunk_bytes(&fragmenter, &payload);

        let probe = SinkProbe::new();
        let mut reassembler = Reassembler::new(total, probe.sink()).unwrap();
        for index in [0u32, 1, 3] {
            assert_eq!(
                reassembler
                    .push(index, total, &chunks[index as usize])
                    .unwrap(),
                Progress::Accepted
            );
        }
        assert!(!reassembler.is_complete());
        assert_eq!(reassembler.received_chunks(), total - 1);
        assert_eq!(reassembler.missing(), vec![2]);
        assert_eq!(reassembler.buffered_chunks(), 1);
        assert_eq!(reassembler.buffered_bytes(), chunks[3].len());

        assert_eq!(
            reassembler.push(2, total, &chunks[2]).unwrap(),
            Progress::Complete
        );
        assert!(reassembler.is_complete());
        assert!(reassembler.missing().is_empty());
        assert_eq!(reassembler.buffered_chunks(), 0);
        assert_eq!(reassembler.buffered_bytes(), 0);
        assert_eq!(probe.bytes(), payload);
    }

    /// 44:V5 bad index, unstable total and oversized fragments are rejected.
    #[test]
    fn u_fragment_reassembly_bad_index_and_total() {
        let probe = SinkProbe::new();
        assert!(matches!(
            Reassembler::new(0, probe.sink()),
            Err(FragmentError::TotalChunksOutOfRange {
                total: 0,
                max: MAX_CHUNKS
            })
        ));
        assert!(matches!(
            Reassembler::new(MAX_CHUNKS + 1, probe.sink()),
            Err(FragmentError::TotalChunksOutOfRange { total, max: MAX_CHUNKS })
                if total == MAX_CHUNKS + 1
        ));

        let full = vec![0u8; CHUNK_PLAIN];
        let tail = vec![0u8; 7];
        let mut reassembler = Reassembler::new(2, probe.sink()).unwrap();
        assert!(matches!(
            reassembler.push(2, 2, &full),
            Err(FragmentError::IndexOutOfRange { index: 2, total: 2 })
        ));
        assert!(matches!(
            reassembler.push(0, 3, &full),
            Err(FragmentError::TotalMismatch {
                expected: 2,
                got: 3
            })
        ));
        let oversized = vec![0u8; CHUNK_PLAIN + 1];
        assert!(matches!(
            reassembler.push(0, 2, &oversized),
            Err(FragmentError::ChunkTooLarge { len, max })
                if len == CHUNK_PLAIN + 1 && max == CHUNK_PLAIN
        ));
        let short = vec![0u8; CHUNK_PLAIN - 1];
        assert!(matches!(
            reassembler.push(0, 2, &short),
            Err(FragmentError::BadChunkLen { index: 0, len, expected })
                if len == CHUNK_PLAIN - 1 && expected == CHUNK_PLAIN
        ));
        assert!(matches!(
            reassembler.push(1, 2, &oversized),
            Err(FragmentError::ChunkTooLarge { .. })
        ));

        assert_eq!(reassembler.push(0, 2, &full).unwrap(), Progress::Accepted);
        assert_eq!(reassembler.push(1, 2, &tail).unwrap(), Progress::Complete);
    }

    /// 44:V5 reorder overflow discards the stream (44 §5.3).
    #[test]
    fn u_fragment_reorder_overflow() {
        let total = 20u32;
        let chunk = vec![0u8; CHUNK_PLAIN];
        let probe = SinkProbe::new();
        let mut reassembler = Reassembler::new(total, probe.sink()).unwrap();
        for index in 1..=MAX_REORDER_CHUNKS as u32 {
            assert_eq!(
                reassembler.push(index, total, &chunk).unwrap(),
                Progress::Accepted
            );
        }
        assert_eq!(reassembler.buffered_chunks(), MAX_REORDER_CHUNKS);
        assert_eq!(reassembler.buffered_bytes(), MAX_REORDER_BYTES);
        assert!(matches!(
            reassembler.push(MAX_REORDER_CHUNKS as u32 + 1, total, &chunk),
            Err(FragmentError::ReorderOverflow { buffered, cap })
                if buffered == MAX_REORDER_CHUNKS && cap == MAX_REORDER_CHUNKS
        ));

        let mut table = SessionTable::new();
        let now = Instant::now();
        let key = key(0x66, StreamId::BLOCK.get());
        let sibling = FragmentKey::new(SessionId(0x66), StreamId::OP_DATA);
        table.open(key, total, probe.sink(), now).unwrap();
        table.open(sibling, total, probe.sink(), now).unwrap();
        for index in 1..=MAX_REORDER_CHUNKS as u32 {
            table.push(key, index, total, &chunk, now).unwrap();
        }
        assert!(matches!(
            table.push(key, MAX_REORDER_CHUNKS as u32 + 1, total, &chunk, now),
            Err(FragmentError::ReorderOverflow { .. })
        ));
        assert_eq!(table.buffered_bytes(), 0);
        assert!(matches!(
            table.push(key, 0, total, &chunk, now),
            Err(FragmentError::UnknownStream { .. })
        ));
        assert_eq!(
            table.push(sibling, 1, total, &chunk, now).unwrap(),
            Progress::Accepted
        );
    }

    /// 44:V5 sink failure closes the stream; `finish` runs once.
    #[test]
    fn u_fragment_sink_error() {
        let full = vec![0u8; CHUNK_PLAIN];
        let tail = vec![0u8; 3];

        let probe = SinkProbe::new();
        let mut reassembler = Reassembler::new(2, probe.failing_finish()).unwrap();
        assert_eq!(reassembler.push(0, 2, &full).unwrap(), Progress::Accepted);
        assert!(matches!(
            reassembler.push(1, 2, &tail),
            Err(FragmentError::Sink(_))
        ));
        assert_eq!(probe.finishes(), 1);
        assert!(!reassembler.is_complete());
        assert!(matches!(
            reassembler.push(1, 2, &tail),
            Err(FragmentError::SinkClosed)
        ));
        assert_eq!(probe.finishes(), 1);

        let probe = SinkProbe::new();
        let mut reassembler = Reassembler::new(2, probe.failing_write()).unwrap();
        assert!(matches!(
            reassembler.push(0, 2, &full),
            Err(FragmentError::Sink(_))
        ));
        assert_eq!(probe.writes(), 0);
        assert!(matches!(
            reassembler.push(0, 2, &full),
            Err(FragmentError::SinkClosed)
        ));
    }

    /// 44:V5 session table caps, TTL, completion and discard rules.
    #[test]
    fn u_fragment_session_table() {
        let now = Instant::now();
        let mut table = SessionTable::new();
        let first = key(0x77, StreamId::BLOCK.get());
        let probe = SinkProbe::new();

        let reassembler = table.open(first, 2, probe.sink(), now).unwrap();
        assert_eq!(reassembler.total_chunks(), 2);
        assert_eq!(table.session_count(), 1);
        assert_eq!(table.stream_count(), 1);
        table.open(first, 2, probe.sink(), now).unwrap();
        assert_eq!(table.stream_count(), 1);
        assert!(matches!(
            table.open(first, 3, probe.sink(), now),
            Err(FragmentError::TotalMismatch {
                expected: 2,
                got: 3
            })
        ));

        let full = vec![0u8; CHUNK_PLAIN];
        let tail = vec![0u8; 4];
        assert_eq!(
            table.push(first, 0, 2, &full, now).unwrap(),
            Progress::Accepted
        );
        assert_eq!(
            table.push(first, 1, 2, &tail, now).unwrap(),
            Progress::Complete
        );
        assert!(table.is_completed(first));
        assert_eq!(table.stream_count(), 0);
        assert_eq!(
            table.push(first, 0, 2, &full, now).unwrap(),
            Progress::Duplicate
        );
        assert_eq!(probe.finishes(), 1);
        assert!(matches!(
            table.open(first, 2, probe.sink(), now),
            Err(FragmentError::Internal)
        ));

        table.close(first);
        assert!(!table.is_completed(first));
        assert_eq!(table.session_count(), 0);
        assert!(matches!(
            table.push(first, 0, 2, &full, now),
            Err(FragmentError::UnknownSession { .. })
        ));

        let mut table = SessionTable::with_limits(2, 2, MAX_BUFFERED_BYTES, SESSION_TTL);
        let session = SessionId(0x88);
        let s1 = FragmentKey::new(session, StreamId(1));
        let s2 = FragmentKey::new(session, StreamId(2));
        let other = key(0x99, 1);
        let third = key(0xaa, 1);
        table.open(s1, 1, probe.sink(), now).unwrap();
        table.open(s2, 1, probe.sink(), now).unwrap();
        table.open(other, 1, probe.sink(), now).unwrap();
        assert!(matches!(
            table.open(FragmentKey::new(session, StreamId(3)), 1, probe.sink(), now),
            Err(FragmentError::StreamFull { max: 2 })
        ));
        assert!(matches!(
            table.open(third, 1, probe.sink(), now),
            Err(FragmentError::SessionFull { max: 2 })
        ));

        let ttl = Duration::from_secs(60);
        let mut table = SessionTable::with_limits(32, 8, MAX_BUFFERED_BYTES, ttl);
        let t0 = now;
        let idle = key(0xbb, 1);
        table.open(idle, 1, probe.sink(), t0).unwrap();
        assert!(table.sweep(t0 + Duration::from_secs(59)).is_empty());
        assert_eq!(table.sweep(t0 + ttl), vec![idle]);
        assert_eq!(table.session_count(), 0);
        assert!(matches!(
            table.push(idle, 0, 1, &[], t0 + ttl),
            Err(FragmentError::UnknownSession { .. })
        ));

        let mut table = SessionTable::with_limits(32, 8, MAX_BUFFERED_BYTES, ttl);
        let probe = SinkProbe::new();
        let done = key(0xcc, 1);
        let keep_alive = key(0xcc, 2);
        table.open(done, 1, probe.sink(), t0).unwrap();
        assert_eq!(table.push(done, 0, 1, &[], t0).unwrap(), Progress::Complete);
        table.open(keep_alive, 2, probe.sink(), t0).unwrap();
        assert_eq!(
            table
                .push(keep_alive, 0, 2, &full, t0 + Duration::from_secs(30))
                .unwrap(),
            Progress::Accepted
        );
        assert_eq!(table.sweep(t0 + ttl), vec![done]);
        assert!(!table.is_completed(done));
        assert_eq!(table.session_count(), 1);
        assert!(matches!(
            table.push(done, 0, 1, &[], t0 + ttl),
            Err(FragmentError::UnknownStream { .. })
        ));

        let mut table = SessionTable::new();
        let k1 = key(0xdd, 1);
        let k2 = key(0xdd, 2);
        table.open(k1, 2, probe.sink(), t0).unwrap();
        table.open(k2, 2, probe.sink(), t0).unwrap();
        assert!(matches!(
            table.push(k1, 0, 3, &full, t0),
            Err(FragmentError::TotalMismatch {
                expected: 2,
                got: 3
            })
        ));
        assert_eq!(table.session_count(), 0);
        assert!(matches!(
            table.push(k1, 0, 2, &full, t0),
            Err(FragmentError::UnknownSession { .. })
        ));
        assert!(matches!(
            table.push(k2, 0, 2, &full, t0),
            Err(FragmentError::UnknownSession { .. })
        ));

        let mut table = SessionTable::new();
        let probe = SinkProbe::new();
        let k1 = key(0xee, 1);
        let k2 = key(0xee, 2);
        table.open(k1, 2, probe.sink(), t0).unwrap();
        table.open(k2, 2, probe.sink(), t0).unwrap();
        assert!(matches!(
            table.push(k1, 5, 2, &[], t0),
            Err(FragmentError::IndexOutOfRange { .. })
        ));
        assert_eq!(table.stream_count(), 1);
        assert!(matches!(
            table.push(k1, 0, 2, &full, t0),
            Err(FragmentError::UnknownStream { .. })
        ));
        assert_eq!(table.push(k2, 0, 2, &full, t0).unwrap(), Progress::Accepted);

        let cap = 2 * CHUNK_PLAIN;
        let mut table = SessionTable::with_limits(4, 8, cap, SESSION_TTL);
        let session = SessionId(0xff);
        let a = FragmentKey::new(session, StreamId(1));
        let b = FragmentKey::new(session, StreamId(2));
        let c = FragmentKey::new(session, StreamId(3));
        for key in [a, b] {
            table.open(key, 2, probe.sink(), t0).unwrap();
            assert_eq!(
                table.push(key, 1, 2, &full, t0).unwrap(),
                Progress::Accepted
            );
        }
        assert_eq!(table.buffered_bytes(), cap);
        table.open(c, 2, probe.sink(), t0).unwrap();
        assert!(matches!(
            table.push(c, 1, 2, &full, t0),
            Err(FragmentError::BufferFull { buffered, cap: ceiling })
                if buffered == 3 * CHUNK_PLAIN && ceiling == cap
        ));
        assert_eq!(table.session_count(), 0);
        assert_eq!(table.buffered_bytes(), 0);
    }

    /// 44:V5 flow-control credit arithmetic (44 §5.4).
    #[test]
    fn u_fragment_credit() {
        let mut credit = Credit::default();
        assert_eq!(credit.granted(), CREDIT_WINDOW);
        assert_eq!(credit.cap(), MAX_CREDIT_WINDOW);
        assert_eq!(credit.available(), CREDIT_WINDOW);
        assert_eq!(credit.in_flight(), 0);

        assert!(credit.try_take(1 << 20));
        assert_eq!(credit.available(), CREDIT_WINDOW - (1 << 20));
        assert!(!credit.try_take(CREDIT_WINDOW));
        assert!(credit.try_take(CREDIT_WINDOW - (1 << 20)));
        assert_eq!(credit.available(), 0);
        assert!(!credit.try_take(1));
        assert_eq!(credit.in_flight(), CREDIT_WINDOW);

        assert_eq!(credit.release(3 << 20), 3 << 20);
        assert_eq!(credit.in_flight(), CREDIT_WINDOW - (3 << 20));
        assert_eq!(credit.release(u32::MAX), CREDIT_WINDOW - (3 << 20));
        assert_eq!(credit.in_flight(), 0);
        assert_eq!(credit.grant(1 << 20), 1 << 20);
        assert_eq!(credit.granted(), CREDIT_WINDOW + (1 << 20));

        let mut full = Credit::new(u32::MAX);
        assert_eq!(full.granted(), MAX_CREDIT_WINDOW);
        assert_eq!(full.cap(), MAX_CREDIT_WINDOW);
        assert_eq!(full.grant(1), 0);
        assert!(full.try_take(1));
        assert!(!full.try_take(u32::MAX));
        assert_eq!(full.available(), MAX_CREDIT_WINDOW - 1);

        let mut small = Credit::with_cap(4 << 20, 2 << 20);
        assert_eq!(small.granted(), 2 << 20);
        assert_eq!(small.cap(), 2 << 20);
        assert_eq!(small.grant(1), 0);
        assert_eq!(small.available(), 2 << 20);
        small.reset(1 << 20);
        assert_eq!(small.granted(), 1 << 20);
        assert_eq!(small.in_flight(), 0);
        small.reset(u32::MAX);
        assert_eq!(small.granted(), 2 << 20);
    }

    fn splitmix(mut state: u64) -> u64 {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// 44:V5 random orders and duplicates still reassemble to the input.
        #[test]
        fn u_fragment_prop_reassembly_roundtrip(
            payload in prop::collection::vec(any::<u8>(), 0..(4 * CHUNK_PLAIN)),
            seed in any::<u64>(),
        ) {
            let total_len = payload.len() as u64;
            let fragmenter =
                Fragmenter::new(SessionId(0x1234), StreamId::BLOCK, total_len).unwrap();
            let total = fragmenter.total_chunks();
            let chunks = chunk_bytes(&fragmenter, &payload);
            let probe = SinkProbe::new();
            let mut reassembler = Reassembler::new(total, probe.sink()).unwrap();

            let mut order: Vec<u32> = (0..total).collect();
            order.sort_by_key(|&index| {
                splitmix(seed ^ u64::from(index).wrapping_mul(0x9e37_79b9_7f4a_7c15))
            });

            let mut completes = 0;
            for &index in &order {
                let progress = reassembler
                    .push(index, total, &chunks[index as usize])
                    .unwrap();
                if progress == Progress::Complete {
                    completes += 1;
                } else {
                    prop_assert_eq!(progress, Progress::Accepted);
                }
                prop_assert_eq!(
                    reassembler
                        .push(index, total, &chunks[index as usize])
                        .unwrap(),
                    Progress::Duplicate
                );
            }
            prop_assert_eq!(completes, 1);
            prop_assert!(reassembler.is_complete());
            prop_assert_eq!(probe.bytes(), payload);
            prop_assert_eq!(probe.finishes(), 1);
        }

        /// 44:V10 arbitrary inputs never panic the fragmentation layer.
        #[test]
        fn u_fragment_prop_arbitrary_inputs_never_panic(
            total_len in any::<u64>(),
            index in any::<u32>(),
            total_chunks in any::<u32>(),
            data in prop::collection::vec(any::<u8>(), 0..=70_000),
        ) {
            if let Ok(fragmenter) =
                Fragmenter::new(SessionId(9), StreamId::OP_DATA, total_len)
            {
                let _ = fragmenter.chunk_len(index);
                let _ = fragmenter.fragment(index, &data);
            }
            let probe = SinkProbe::new();
            if let Ok(mut reassembler) = Reassembler::new(total_chunks, probe.sink()) {
                let _ = reassembler.push(index, total_chunks, &data);
                let _ = reassembler.missing();
            }
            let mut table = SessionTable::new();
            let key = FragmentKey::new(SessionId(10), StreamId(3));
            let now = Instant::now();
            let _ = table.open(key, total_chunks, probe.sink(), now);
            let _ = table.push(key, index, total_chunks, &data, now);
        }
    }
}
