//! Reassembly of steady-state `STREAM_DATA` into plaintext for the replayer.
//!
//! A writer sends one relay stream (`StreamId::OP_DATA`) per data operation
//! and then an `ORDERED` frame whose `DataRef` names that stream. The downlink
//! delivers both on the same ordered HTTP body, so by the time the replayer
//! asks for the bytes they are either complete or the frame was malformed.
//!
//! The cache is volatile: it holds only streams from the current connection.
//! Completed streams are capped, because a reader only needs the most recent
//! echo window; older operations have already been materialised.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::client::replayer::OpData;
use crate::protocol::crypto::{CryptoError, Opener};
use crate::protocol::fragment::CHUNK_PLAIN;
use crate::protocol::{DataRef, FrameBuf, ProtocolError, SessionId, StreamId};
use crate::store::Errno;

/// Completed streams kept for late `ORDERED` frames.
const COMPLETED_CAPACITY: usize = 64;
/// Out-of-order fragments buffered per stream.
const REORDER_CHUNKS: usize = 8;
/// Out-of-order bytes buffered per stream.
const REORDER_BYTES: usize = 8 * CHUNK_PLAIN;

/// Why a `STREAM_DATA` frame could not be accepted.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DataError {
    /// The frame had no route prefix.
    #[error("STREAM_DATA has no route prefix")]
    NoRoute,
    /// The AEAD envelope failed.
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    /// The frame itself was malformed.
    #[error("frame: {0}")]
    Protocol(#[from] ProtocolError),
    /// A fragment had the wrong width for its position.
    #[error("fragment {index} has length {len}, expected {expected}")]
    BadChunkLen {
        /// Fragment index.
        index: u32,
        /// Observed length.
        len: usize,
        /// Required length.
        expected: usize,
    },
    /// The stream's chunk count changed.
    #[error("fragment total changed from {expected} to {got}")]
    TotalMismatch {
        /// Original total.
        expected: u32,
        /// Observed total.
        got: u32,
    },
    /// A fragment index was outside the stream.
    #[error("fragment index {index} outside total {total}")]
    IndexOutOfRange {
        /// Observed index.
        index: u32,
        /// Stream total.
        total: u32,
    },
    /// Too many out-of-order fragments.
    #[error("fragment reorder buffer overflow")]
    ReorderOverflow,
}

/// One in-flight relay stream.
struct StreamState {
    total: u32,
    next: u32,
    bytes: Vec<u8>,
    pending: BTreeMap<u32, Vec<u8>>,
    pending_bytes: usize,
}

impl StreamState {
    fn new(total: u32) -> Self {
        Self {
            total,
            next: 0,
            bytes: Vec::new(),
            pending: BTreeMap::new(),
            pending_bytes: 0,
        }
    }

    /// Feed one fragment; returns true when the stream is complete.
    fn push(&mut self, index: u32, total: u32, data: &[u8]) -> Result<bool, DataError> {
        if total != self.total {
            return Err(DataError::TotalMismatch {
                expected: self.total,
                got: total,
            });
        }
        if index >= self.total {
            return Err(DataError::IndexOutOfRange {
                index,
                total: self.total,
            });
        }
        if index + 1 < self.total {
            if data.len() != CHUNK_PLAIN {
                return Err(DataError::BadChunkLen {
                    index,
                    len: data.len(),
                    expected: CHUNK_PLAIN,
                });
            }
        } else if data.len() > CHUNK_PLAIN {
            return Err(DataError::BadChunkLen {
                index,
                len: data.len(),
                expected: CHUNK_PLAIN,
            });
        }
        if index < self.next || self.pending.contains_key(&index) {
            return Ok(false);
        }
        if index == self.next {
            self.bytes.extend_from_slice(data);
            self.next += 1;
            while let Some(buffered) = self.pending.remove(&self.next) {
                self.pending_bytes = self.pending_bytes.saturating_sub(buffered.len());
                self.bytes.extend_from_slice(&buffered);
                self.next += 1;
            }
        } else {
            if self.pending.len() >= REORDER_CHUNKS
                || self.pending_bytes.saturating_add(data.len()) > REORDER_BYTES
            {
                return Err(DataError::ReorderOverflow);
            }
            self.pending_bytes = self.pending_bytes.saturating_add(data.len());
            self.pending.insert(index, data.to_vec());
        }
        Ok(self.next == self.total)
    }
}

#[derive(Default)]
struct Inner {
    streams: HashMap<SessionId, StreamState>,
    completed: HashMap<SessionId, Vec<u8>>,
    order: VecDeque<SessionId>,
}

/// Volatile plaintext cache keyed by data session.
#[derive(Default)]
pub struct DataCache {
    inner: Mutex<Inner>,
}

impl fmt::Debug for DataCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.lock();
        formatter
            .debug_struct("DataCache")
            .field("streams", &inner.streams.len())
            .field("completed", &inner.completed.len())
            .finish()
    }
}

impl DataCache {
    /// Empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Open and reassemble one `STREAM_DATA` frame.
    ///
    /// Frames for streams other than `OP_DATA` are ignored: they belong to
    /// the sync relay and are not write payloads.
    pub fn push(&self, frame: &FrameBuf, opener: &Opener<'_>) -> Result<(), DataError> {
        let Some(route) = frame.prefix.as_route() else {
            return Err(DataError::NoRoute);
        };
        if route.stream != StreamId::OP_DATA {
            return Ok(());
        }
        let plaintext = opener.open(&frame.header, &frame.prefix, &frame.body)?;
        let mut inner = self.lock();
        let mut state = inner
            .streams
            .remove(&route.session_id)
            .unwrap_or_else(|| StreamState::new(route.total_chunks));
        let complete = state.push(route.chunk_index, route.total_chunks, plaintext.as_slice())?;
        if complete {
            inner.completed.insert(route.session_id, state.bytes);
            inner.order.push_back(route.session_id);
            while inner.order.len() > COMPLETED_CAPACITY {
                if let Some(oldest) = inner.order.pop_front() {
                    inner.completed.remove(&oldest);
                }
            }
        } else {
            inner.streams.insert(route.session_id, state);
        }
        Ok(())
    }

    /// Number of completed streams (diagnostics and tests).
    pub fn completed_len(&self) -> usize {
        self.lock().completed.len()
    }

    /// Number of in-flight streams (diagnostics and tests).
    pub fn stream_len(&self) -> usize {
        self.lock().streams.len()
    }
}

impl OpData for DataCache {
    fn read(&self, data: &DataRef) -> Result<Vec<u8>, Errno> {
        self.lock()
            .completed
            .get(&data.session)
            .cloned()
            .ok_or(Errno::EIO)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::protocol::crypto::{ClusterId, KeyRing, NonceMinter, Sealer};
    use crate::protocol::fragment::Fragmenter;
    use crate::protocol::{Flags, FrameHeader, MsgType, Prefix, RoutePrefix, Seq, StreamId};

    fn ring() -> KeyRing {
        KeyRing::derive(&[7u8; 32], &ClusterId::from_bytes([9u8; 16])).expect("ring")
    }

    fn fragment_frame(
        sealer: &Sealer<'_>,
        session: SessionId,
        index: u32,
        total: u32,
        data: &[u8],
    ) -> FrameBuf {
        let mut header = FrameHeader::new(
            MsgType::STREAM_DATA,
            Flags::ENC.with(Flags::ROUTED),
            0,
            Seq::UNSEQUENCED,
        );
        let prefix = Prefix::Route(RoutePrefix::new(session, StreamId::OP_DATA, index, total));
        let sealed = sealer
            .seal(&mut header, &prefix, data)
            .expect("seal fragment");
        FrameBuf::new(header, prefix, sealed.into_vec())
    }

    #[test]
    fn u_data_cache_reassembles_and_serves_opdata() {
        let ring = ring();
        let nonces = NonceMinter::with_instance(1);
        let sealer = Sealer::new(&ring, &nonces);
        let opener = Opener::new(&ring);
        let session = SessionId::new(0x55);
        let payload = b"hello over stream data";
        let fragmenter =
            Fragmenter::new(session, StreamId::OP_DATA, payload.len() as u64).expect("fragmenter");
        assert_eq!(fragmenter.total_chunks(), 1);

        let cache = DataCache::new();
        let frame = fragment_frame(&sealer, session, 0, 1, payload);
        cache.push(&frame, &opener).expect("push");
        assert_eq!(cache.completed_len(), 1);
        assert_eq!(cache.stream_len(), 0);

        let reference = DataRef {
            session,
            total_len: payload.len() as u64,
            data_hash: *blake3::hash(payload).as_bytes(),
        };
        assert_eq!(cache.read(&reference), Ok(payload.to_vec()));
    }

    #[test]
    fn u_data_cache_reorders_two_fragments() {
        let ring = ring();
        let nonces = NonceMinter::with_instance(2);
        let sealer = Sealer::new(&ring, &nonces);
        let opener = Opener::new(&ring);
        let session = SessionId::new(0x66);
        let payload = vec![0x5a; CHUNK_PLAIN + 7];
        let fragmenter =
            Fragmenter::new(session, StreamId::OP_DATA, payload.len() as u64).expect("fragmenter");
        assert_eq!(fragmenter.total_chunks(), 2);

        let cache = DataCache::new();
        let second = fragment_frame(&sealer, session, 1, 2, &payload[CHUNK_PLAIN..]);
        let first = fragment_frame(&sealer, session, 0, 2, &payload[..CHUNK_PLAIN]);
        cache.push(&second, &opener).expect("second");
        assert_eq!(cache.completed_len(), 0);
        cache.push(&first, &opener).expect("first");
        assert_eq!(cache.completed_len(), 1);

        let reference = DataRef {
            session,
            total_len: payload.len() as u64,
            data_hash: *blake3::hash(&payload).as_bytes(),
        };
        assert_eq!(cache.read(&reference), Ok(payload));
    }

    #[test]
    fn u_data_cache_ignores_non_op_data_streams() {
        let ring = ring();
        let nonces = NonceMinter::with_instance(3);
        let sealer = Sealer::new(&ring, &nonces);
        let opener = Opener::new(&ring);
        let session = SessionId::new(0x77);
        let mut header = FrameHeader::new(
            MsgType::STREAM_DATA,
            Flags::ENC.with(Flags::ROUTED),
            0,
            Seq::UNSEQUENCED,
        );
        let prefix = Prefix::Route(RoutePrefix::new(session, StreamId::BLOCK, 0, 1));
        let sealed = sealer.seal(&mut header, &prefix, b"block").expect("seal");
        let frame = FrameBuf::new(header, prefix, sealed.into_vec());
        let cache = DataCache::new();
        cache.push(&frame, &opener).expect("ignored");
        assert_eq!(cache.completed_len(), 0);
        assert_eq!(cache.stream_len(), 0);
    }
}
