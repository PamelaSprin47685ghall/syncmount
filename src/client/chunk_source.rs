//! Relay-backed chunk source: local cache first, then `BLOCK_REQ`.
//!
//! Owner: client transport. See 43 §5.1/§5.3 and the JOIN manifest-only path.
//!
//! # Two identities, two checks
//!
//! `put` seals local plaintext and stores it. `fetch` first reads the local
//! [`VerifiedChunkStore`]; a miss sends one `BLOCK_REQ` and receives the
//! sealed blob over `STREAM_DATA{BLOCK}`. The blob enters the cache only
//! through [`VerifiedChunkStore::put_blob`], which checks
//! `BLAKE3(blob) == blob_id` and then `BLAKE3(open(blob)) == chunk_id`.
//! Only verified plaintext leaves `fetch`.
//!
//! # Retry
//!
//! `BLOCK_MISS` and a timed-out block stream are retried within a bounded
//! budget; a blob that fails either identity check is reported as
//! [`SyncError::ChunkCorrupt`] and never cached. Out-of-order and duplicate
//! fragments are handled by the link's assembler, and every fragment
//! releases its relay credit with `FLOW`.
//!
//! # Plan fetch
//!
//! [`fetch_blocks`] walks a [`DiffPlan`], includes `TypeReplace` items, and
//! fetches every block identity once (content addressing deduplicates across
//! files). Failures are collected rather than aborting the walk, so one bad
//! block does not hide the rest.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::store::Kind;
use crate::sync::chunk::{ChunkId, ChunkKind, VerifiedChunkStore};
use crate::sync::manifest::{Blockmap, BlockmapIndex, Manifest};
use crate::sync::{BoxFut, ChunkSource, DiffPlan, SyncError};

use super::sync_link::{RelayError, RelaySyncLink};

/// Attempts per block before the fetch reports the chunk unavailable.
pub const DEFAULT_BLOCK_ATTEMPTS: u32 = 3;

/// Pause before retrying a `BLOCK_MISS` or a timed-out stream.
pub const DEFAULT_RETRY_BACKOFF: Duration = Duration::from_millis(100);

/// A relay-backed [`ChunkSource`].
pub struct RelayChunkSource {
    link: Arc<RelaySyncLink>,
    store: Arc<VerifiedChunkStore>,
    attempts: u32,
    backoff: Duration,
}

impl fmt::Debug for RelayChunkSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayChunkSource")
            .field("link", &self.link)
            .field("store", &self.store)
            .field("attempts", &self.attempts)
            .finish_non_exhaustive()
    }
}

impl RelayChunkSource {
    /// Bind a verified cache to a relay link.
    pub fn new(link: Arc<RelaySyncLink>, store: Arc<VerifiedChunkStore>) -> Self {
        Self {
            link,
            store,
            attempts: DEFAULT_BLOCK_ATTEMPTS,
            backoff: DEFAULT_RETRY_BACKOFF,
        }
    }

    /// Replace the retry budget and backoff.
    pub fn with_retry(mut self, attempts: u32, backoff: Duration) -> Self {
        self.attempts = attempts.max(1);
        self.backoff = backoff;
        self
    }

    /// The shared verified cache.
    pub fn store(&self) -> &Arc<VerifiedChunkStore> {
        &self.store
    }

    fn cached(&self, kind: ChunkKind, id: ChunkId) -> Result<Option<Vec<u8>>, SyncError> {
        match self.store.get(kind, &id) {
            Ok(Some(plaintext)) => Ok(Some(plaintext.to_vec())),
            Ok(None) => Ok(None),
            Err(_) => {
                // A corrupt cache entry is a miss, not a fatal join error:
                // drop it and re-fetch the authenticated bytes.
                let _ = self.store.evict(kind, &id);
                Ok(None)
            }
        }
    }
}

impl ChunkSource for RelayChunkSource {
    fn put(&self, kind: ChunkKind, plain: &[u8]) -> Result<ChunkId, SyncError> {
        let (id, _) = self
            .store
            .put_plaintext(kind, plain)
            .map_err(|error| SyncError::Io(format!("chunk store put: {error}")))?;
        Ok(id)
    }

    fn fetch(&self, kind: ChunkKind, id: ChunkId) -> BoxFut<'_, Result<Vec<u8>, SyncError>> {
        Box::pin(async move {
            if let Some(plaintext) = self.cached(kind, id)? {
                return Ok(plaintext);
            }
            let mut last = SyncError::ChunkUnavailable { id };
            for attempt in 0..self.attempts {
                if attempt > 0 {
                    tokio::time::sleep(self.backoff).await;
                }
                // A concurrent fetch may have completed while this one
                // waited for the block gate.
                if let Some(plaintext) = self.cached(kind, id)? {
                    return Ok(plaintext);
                }
                let blob = match self.link.request_block_blob(kind, id).await {
                    Ok(blob) => blob,
                    Err(RelayError::BlockMiss) => {
                        last = SyncError::ChunkUnavailable { id };
                        continue;
                    }
                    Err(RelayError::Timeout { .. }) => {
                        last = SyncError::Link(format!("block {id} timed out"));
                        continue;
                    }
                    Err(error) => return Err(SyncError::Link(error.to_string())),
                };
                if self.store.put_blob(kind, &id, &blob).is_err() {
                    // The peer sent bytes that fail the physical or the
                    // plaintext identity check. Retrying the same peer would
                    // only repeat the corruption.
                    return Err(SyncError::ChunkCorrupt { id });
                }
                return match self.store.get(kind, &id) {
                    Ok(Some(plaintext)) => Ok(plaintext.to_vec()),
                    Ok(None) => Err(SyncError::ChunkUnavailable { id }),
                    Err(_) => Err(SyncError::ChunkCorrupt { id }),
                };
            }
            Err(last)
        })
    }
}

/// One block that could not be fetched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockFetchFailure {
    /// Manifest path that needs the block.
    pub path: String,
    /// Zero-based block within the file, when the blockmap named it.
    pub block: u32,
    /// Content identity, when the blockmap named it.
    pub id: Option<ChunkId>,
    /// The failure exactly as the fetch or the blockmap check produced it.
    pub error: SyncError,
}

/// What [`fetch_blocks`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockFetchReport {
    /// Files that needed at least one block.
    pub files: u64,
    /// Distinct block identities considered.
    pub blocks: u64,
    /// Distinct blocks fetched and verified.
    pub fetched: u64,
    /// Repeated identities skipped by content addressing.
    pub duplicates: u64,
    /// Failures, in plan order.
    pub failures: Vec<BlockFetchFailure>,
}

impl BlockFetchReport {
    /// True when every block was fetched.
    pub fn is_ok(&self) -> bool {
        self.failures.is_empty()
    }

    /// The first failure, unchanged, or the report itself.
    ///
    /// A block-count disagreement is reported as
    /// `SyncError::Format("blockmap disagrees with manifest")`; a chunk error
    /// keeps its own variant and detail.
    ///
    /// # Errors
    ///
    /// The first [`BlockFetchFailure::error`].
    pub fn into_result(self) -> Result<Self, SyncError> {
        if let Some(failure) = self.failures.first() {
            return Err(failure.error.clone());
        }
        Ok(self)
    }
}

/// Fetch every block a [`DiffPlan`] needs, including `TypeReplace` items.
///
/// `plan`, `remote` and `blockmap` must describe the same sequence; the
/// caller normally gets them from one JOIN (`ManifestService` and
/// `ClusterWins`). The walk is sequential: one relay session carries one
/// `STREAM_DATA{BLOCK}` stream at a time, and the local cache answers the
/// rest.
pub async fn fetch_blocks(
    plan: &DiffPlan,
    remote: &Manifest,
    blockmap: &Blockmap,
    source: &dyn ChunkSource,
) -> BlockFetchReport {
    let mut report = BlockFetchReport::default();
    let mut seen = HashSet::new();

    for item in plan.transfers() {
        let Some(index) = item.remote else {
            report.failures.push(BlockFetchFailure {
                path: item.path.clone(),
                block: 0,
                id: None,
                error: SyncError::Format("transfer item has no remote manifest entry"),
            });
            continue;
        };
        let Some(entry) = remote.entry(index) else {
            report.failures.push(BlockFetchFailure {
                path: item.path.clone(),
                block: 0,
                id: None,
                error: SyncError::Format("manifest entry is missing"),
            });
            continue;
        };
        if entry.kind != Kind::File || entry.block_count == 0 {
            continue;
        }
        report.files += 1;
        let Some(ids) = blockmap.file_blocks(index) else {
            report.failures.push(BlockFetchFailure {
                path: item.path.clone(),
                block: 0,
                id: None,
                error: SyncError::Format("blockmap part for this file was not fetched"),
            });
            continue;
        };
        if ids.len() as u32 != entry.block_count {
            report.failures.push(BlockFetchFailure {
                path: item.path.clone(),
                block: 0,
                id: None,
                error: SyncError::Format("blockmap disagrees with manifest"),
            });
            continue;
        }
        for (block, id) in ids.into_iter().enumerate() {
            let block = u32::try_from(block).unwrap_or(u32::MAX);
            if !seen.insert(id) {
                report.duplicates += 1;
                continue;
            }
            report.blocks += 1;
            match source.fetch(ChunkKind::File, id).await {
                Ok(_) => report.fetched += 1,
                Err(error) => report.failures.push(BlockFetchFailure {
                    path: item.path.clone(),
                    block,
                    id: Some(id),
                    error,
                }),
            }
        }
    }
    report
}

/// Blockmap parts a plan needs, for callers that only have the index.
///
/// This mirrors [`DiffPlan::blockmap_parts`] but also includes `TypeReplace`
/// items, which the ticket calls out explicitly.
pub fn blockmap_parts_for_plan(
    plan: &DiffPlan,
    index: &BlockmapIndex,
    remote: &Manifest,
) -> Vec<u32> {
    let mut parts = std::collections::BTreeSet::new();
    for item in plan.transfers() {
        let Some(entry_index) = item.remote else {
            continue;
        };
        let Some(entry) = remote.entry(entry_index) else {
            continue;
        };
        if entry.kind != Kind::File || entry.block_count == 0 {
            continue;
        }
        let Some((first, count)) = index.block_range(entry_index) else {
            continue;
        };
        for part in index.parts_for_range(first, count) {
            parts.insert(part);
        }
    }
    parts.into_iter().collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use super::*;
    use crate::client::sync_link::RelaySyncLink;
    use crate::protocol::crypto::{ClusterId, KeyRing, NonceMinter, Opener, Sealer};
    use crate::protocol::fragment::{CHUNK_PLAIN, Fragmenter};
    use crate::protocol::messages::{RelaySub, WcpWriter, fid};
    use crate::protocol::{
        Flags, FrameBuf, FrameHeader, Limits, Message, MsgType, Prefix, RoutePrefix, Seq,
        SessionId, StreamId, decode_sealed,
    };
    use crate::store::InodeId;
    use crate::store::RootFd;
    use crate::store::chunk_store::CHUNK_BYTES;
    use crate::sync::manifest::Entry;
    use crate::sync::{DiskStat, LocalManifest, LocalTree};
    use tempfile::TempDir;
    use tokio::sync::mpsc;

    const KEY: [u8; 32] = [0x31; 32];
    static NONCE_INSTANCE: AtomicU64 = AtomicU64::new(1);

    fn nonces() -> NonceMinter {
        NonceMinter::with_instance(NONCE_INSTANCE.fetch_add(1, Ordering::Relaxed))
    }

    fn ring() -> Arc<KeyRing> {
        Arc::new(
            KeyRing::derive(&[7u8; 32], &ClusterId::from_bytes([9u8; 16]))
                .expect("derive key ring"),
        )
    }

    fn store(tag: &str) -> (TempDir, Arc<VerifiedChunkStore>) {
        let tmp = TempDir::new().unwrap_or_else(|error| panic!("tempdir {tag}: {error}"));
        let mount = tmp.path().join("mnt");
        std::fs::create_dir(&mount).unwrap_or_else(|error| panic!("mkdir {tag}: {error}"));
        let root = Arc::new(
            RootFd::open_before_mount(&mount).unwrap_or_else(|error| panic!("root {tag}: {error}")),
        );
        let store = VerifiedChunkStore::open(root, KEY)
            .unwrap_or_else(|error| panic!("store {tag}: {error}"));
        (tmp, Arc::new(store))
    }

    fn seal_stream(
        ring: &KeyRing,
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
        let prefix = Prefix::Route(RoutePrefix::new(session, StreamId::BLOCK, index, total));
        let sealed = Sealer::new(ring, &nonces())
            .seal(&mut header, &prefix, data)
            .expect("seal fragment");
        FrameBuf::new(header, prefix, sealed.into_vec())
    }

    fn request_fields(frame: &FrameBuf, ring: &KeyRing) -> (u64, ChunkKind, ChunkId) {
        let plaintext = Opener::new(ring)
            .open(&frame.header, &frame.prefix, &frame.body)
            .expect("open request");
        let Message::Relay(relay) =
            decode_sealed(MsgType::RELAY, plaintext.as_slice(), &Limits::default()).expect("relay")
        else {
            panic!("not a relay");
        };
        assert_eq!(relay.sub, RelaySub::BlockReq);
        let extra = relay.fields.get(fid::F_EXTRA).expect("F_EXTRA");
        let id = u64::from_le_bytes(extra[..8].try_into().expect("id"));
        let kind = ChunkKind::from_wire(extra[8]).expect("kind");
        let raw = relay.fields.get(fid::F_CHUNK_ID).expect("F_CHUNK_ID");
        let mut chunk = [0u8; 32];
        chunk.copy_from_slice(raw);
        (id, kind, ChunkId::from_bytes(chunk))
    }

    fn block_miss(ring: &KeyRing, session: SessionId, id: u64) -> FrameBuf {
        let mut writer = WcpWriter::new();
        writer.u8(fid::F_SUB_KIND, RelaySub::BlockMiss.as_u8());
        writer.bytes(fid::F_EXTRA, &id.to_le_bytes());
        let body = writer.finish().expect("body");
        let prefix = Prefix::Route(RoutePrefix::new(session, StreamId::CTRL, 0, 0));
        let mut header = FrameHeader::new(
            MsgType::RELAY,
            Flags::ENC.with(Flags::ROUTED),
            0,
            Seq::UNSEQUENCED,
        );
        let sealed = Sealer::new(ring, &nonces())
            .seal(&mut header, &prefix, &body)
            .expect("seal miss");
        FrameBuf::new(header, prefix, sealed.into_vec())
    }

    async fn next_block_req(rx: &mut mpsc::Receiver<FrameBuf>, ring: &KeyRing) -> FrameBuf {
        loop {
            let frame = rx.recv().await.expect("relay frame");
            if frame.header.msg_type != MsgType::RELAY {
                continue;
            }
            let plaintext = Opener::new(ring)
                .open(&frame.header, &frame.prefix, &frame.body)
                .expect("open request");
            let Message::Relay(relay) =
                decode_sealed(MsgType::RELAY, plaintext.as_slice(), &Limits::default())
                    .expect("relay")
            else {
                continue;
            };
            if relay.sub == RelaySub::BlockReq {
                return frame;
            }
        }
    }

    async fn send_stream(
        link: &RelaySyncLink,
        ring: &KeyRing,
        session: SessionId,
        blob: &[u8],
        order: &[u32],
        truncate: bool,
    ) {
        let fragmenter =
            Fragmenter::new(session, StreamId::BLOCK, blob.len() as u64).expect("fragmenter");
        let total = fragmenter.total_chunks();
        let mut indexes: Vec<u32> = order.to_vec();
        if indexes.is_empty() {
            indexes = (0..total).collect();
        }
        if truncate {
            indexes.retain(|index| *index + 1 < total);
        }
        for index in indexes {
            let length = fragmenter.chunk_len(index).expect("chunk len");
            let start = index as usize * CHUNK_PLAIN;
            let frame = seal_stream(ring, session, index, total, &blob[start..start + length]);
            assert!(link.deliver_stream(&frame).await.expect("deliver"));
        }
    }

    #[tokio::test]
    async fn u_chunk_source_fetches_blob_and_returns_plaintext() {
        let ring = ring();
        let session = SessionId::new(0x501);
        let (_peer_tmp, peer) = store("fetch-peer");
        let (_client_tmp, client) = store("fetch-client");
        let plaintext = vec![0x5a; CHUNK_BYTES];
        let (id, _) = peer
            .put_plaintext(ChunkKind::File, &plaintext)
            .expect("put");
        let blob = peer
            .get_blob(ChunkKind::File, &id)
            .expect("get blob")
            .expect("blob");
        let (control_tx, mut control_rx) = mpsc::channel(64);
        let link = Arc::new(RelaySyncLink::new(
            Arc::new(control_tx),
            Arc::clone(&ring),
            session,
        ));
        let source = RelayChunkSource::new(Arc::clone(&link), Arc::clone(&client));
        let responder_link = Arc::clone(&link);
        let responder_ring = Arc::clone(&ring);
        let task = tokio::spawn(async move {
            let frame = next_block_req(&mut control_rx, &responder_ring).await;
            let (_, kind, chunk) = request_fields(&frame, &responder_ring);
            assert_eq!(kind, ChunkKind::File);
            assert_eq!(chunk, id);
            send_stream(&responder_link, &responder_ring, session, &blob, &[], false).await;
        });
        let fetched = source.fetch(ChunkKind::File, id).await.expect("fetch");
        assert_eq!(fetched, plaintext);
        task.await.expect("responder");
    }

    #[tokio::test]
    async fn u_chunk_source_rejects_tampered_blob() {
        let ring = ring();
        let session = SessionId::new(0x502);
        let (_peer_tmp, peer) = store("tamper-peer");
        let (_client_tmp, client) = store("tamper-client");
        let plaintext = b"authenticated bytes";
        let (id, _) = peer.put_plaintext(ChunkKind::File, plaintext).expect("put");
        let mut blob = peer
            .get_blob(ChunkKind::File, &id)
            .expect("get blob")
            .expect("blob");
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        let (control_tx, mut control_rx) = mpsc::channel(64);
        let link = Arc::new(RelaySyncLink::new(
            Arc::new(control_tx),
            Arc::clone(&ring),
            session,
        ));
        let source = RelayChunkSource::new(Arc::clone(&link), Arc::clone(&client));
        let responder_link = Arc::clone(&link);
        let responder_ring = Arc::clone(&ring);
        let task = tokio::spawn(async move {
            let _frame = next_block_req(&mut control_rx, &responder_ring).await;
            send_stream(&responder_link, &responder_ring, session, &blob, &[], false).await;
        });
        let error = source
            .fetch(ChunkKind::File, id)
            .await
            .expect_err("tampered blob must fail");
        assert!(matches!(error, SyncError::ChunkCorrupt { id: bad } if bad == id));
        assert!(!client.has(ChunkKind::File, &id));
        task.await.expect("responder");
    }

    #[tokio::test]
    async fn u_chunk_source_retries_block_miss() {
        let ring = ring();
        let session = SessionId::new(0x503);
        let (_peer_tmp, peer) = store("miss-peer");
        let (_client_tmp, client) = store("miss-client");
        let plaintext = b"retry after miss";
        let (id, _) = peer.put_plaintext(ChunkKind::File, plaintext).expect("put");
        let blob = peer
            .get_blob(ChunkKind::File, &id)
            .expect("get blob")
            .expect("blob");
        let (control_tx, mut control_rx) = mpsc::channel(64);
        let link = Arc::new(RelaySyncLink::new(
            Arc::new(control_tx),
            Arc::clone(&ring),
            session,
        ));
        let source = RelayChunkSource::new(Arc::clone(&link), Arc::clone(&client))
            .with_retry(3, Duration::ZERO);
        let responder_link = Arc::clone(&link);
        let responder_ring = Arc::clone(&ring);
        let task = tokio::spawn(async move {
            let frame = next_block_req(&mut control_rx, &responder_ring).await;
            let (request_id, _, _) = request_fields(&frame, &responder_ring);
            let miss = block_miss(&responder_ring, session, request_id);
            assert!(responder_link.deliver(&miss));
            let _second = next_block_req(&mut control_rx, &responder_ring).await;
            send_stream(&responder_link, &responder_ring, session, &blob, &[], false).await;
        });
        let fetched = source
            .fetch(ChunkKind::File, id)
            .await
            .expect("fetch after miss");
        assert_eq!(fetched, plaintext);
        task.await.expect("responder");
    }

    #[tokio::test]
    async fn u_chunk_source_retries_truncated_stream() {
        let ring = ring();
        let session = SessionId::new(0x504);
        let (_peer_tmp, peer) = store("truncated-peer");
        let (_client_tmp, client) = store("truncated-client");
        let plaintext = vec![0x77; CHUNK_PLAIN + 10];
        let (id, _) = peer
            .put_plaintext(ChunkKind::File, &plaintext)
            .expect("put");
        let blob = peer
            .get_blob(ChunkKind::File, &id)
            .expect("get blob")
            .expect("blob");
        let (control_tx, mut control_rx) = mpsc::channel(64);
        let link = Arc::new(
            RelaySyncLink::new(Arc::new(control_tx), Arc::clone(&ring), session)
                .with_timeout(Duration::from_millis(60)),
        );
        let source = RelayChunkSource::new(Arc::clone(&link), Arc::clone(&client))
            .with_retry(3, Duration::ZERO);
        let responder_link = Arc::clone(&link);
        let responder_ring = Arc::clone(&ring);
        let task = tokio::spawn(async move {
            let _first = next_block_req(&mut control_rx, &responder_ring).await;
            // Send only fragment 0 of a two-fragment stream.
            send_stream(&responder_link, &responder_ring, session, &blob, &[0], true).await;
            let _second = next_block_req(&mut control_rx, &responder_ring).await;
            send_stream(&responder_link, &responder_ring, session, &blob, &[], false).await;
        });
        let fetched = source
            .fetch(ChunkKind::File, id)
            .await
            .expect("fetch after truncation");
        assert_eq!(fetched, plaintext);
        task.await.expect("responder");
    }

    #[tokio::test]
    async fn u_chunk_source_accepts_out_of_order_duplicates() {
        let ring = ring();
        let session = SessionId::new(0x505);
        let (_peer_tmp, peer) = store("order-peer");
        let (_client_tmp, client) = store("order-client");
        let plaintext = vec![0x33; CHUNK_PLAIN + 1];
        let (id, _) = peer
            .put_plaintext(ChunkKind::File, &plaintext)
            .expect("put");
        let blob = peer
            .get_blob(ChunkKind::File, &id)
            .expect("get blob")
            .expect("blob");
        let (control_tx, mut control_rx) = mpsc::channel(64);
        let link = Arc::new(RelaySyncLink::new(
            Arc::new(control_tx),
            Arc::clone(&ring),
            session,
        ));
        let source = RelayChunkSource::new(Arc::clone(&link), Arc::clone(&client));
        let responder_link = Arc::clone(&link);
        let responder_ring = Arc::clone(&ring);
        let task = tokio::spawn(async move {
            let _frame = next_block_req(&mut control_rx, &responder_ring).await;
            send_stream(
                &responder_link,
                &responder_ring,
                session,
                &blob,
                &[1, 1, 0],
                false,
            )
            .await;
        });
        let fetched = source.fetch(ChunkKind::File, id).await.expect("fetch");
        assert_eq!(fetched, plaintext);
        task.await.expect("responder");
    }

    #[derive(Debug)]
    struct RecordingSource {
        seen: Mutex<Vec<ChunkId>>,
        fail: Option<ChunkId>,
    }

    impl ChunkSource for RecordingSource {
        fn put(&self, _kind: ChunkKind, _plain: &[u8]) -> Result<ChunkId, SyncError> {
            Err(SyncError::Io("read-only test source".to_owned()))
        }

        fn fetch(&self, _kind: ChunkKind, id: ChunkId) -> BoxFut<'_, Result<Vec<u8>, SyncError>> {
            Box::pin(async move {
                self.seen
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(id);
                if self.fail == Some(id) {
                    return Err(SyncError::ChunkUnavailable { id });
                }
                Ok(Vec::new())
            })
        }
    }

    #[derive(Debug)]
    struct TypeReplaceTree;

    impl LocalTree for TypeReplaceTree {
        fn walk(&self) -> Result<Vec<(String, DiskStat)>, SyncError> {
            Ok(vec![("file".to_owned(), DiskStat::dir(7, 0o755))])
        }

        fn stat(&self, _path: &str) -> Result<Option<DiskStat>, SyncError> {
            Ok(None)
        }

        fn cached_manifest(&self) -> Option<LocalManifest> {
            None
        }
    }

    #[tokio::test]
    async fn u_fetch_blocks_includes_type_replace_and_reports_failure() {
        let block_a = ChunkId::of_plaintext(b"a");
        let block_b = ChunkId::of_plaintext(b"b");
        let remote = Manifest::try_new(
            Seq(3),
            vec![Entry::file(
                "file",
                InodeId::from_bytes([1u8; 16]),
                0o644,
                1000,
                1000,
                2,
                7,
                &[block_a, block_b],
            )],
        )
        .expect("manifest");
        let blockmap = Blockmap::new(Seq(3), vec![0], vec![block_a, block_b]).expect("blockmap");
        // A directory on disk where the manifest has a file classifies as
        // `TypeReplace`; the block walk must include it.
        let plan = crate::sync::manifest::diff::plan(
            None,
            &remote,
            &TypeReplaceTree,
            ClusterId::from_bytes([1u8; 16]),
        )
        .expect("plan");
        assert!(
            plan.transfers()
                .any(|item| item.kind == crate::sync::DiffKind::TypeReplace)
        );
        let source = RecordingSource {
            seen: Mutex::new(Vec::new()),
            fail: Some(block_b),
        };
        let report = fetch_blocks(&plan, &remote, &blockmap, &source).await;
        assert_eq!(report.files, 1);
        assert_eq!(report.blocks, 2);
        assert_eq!(report.fetched, 1);
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].id, Some(block_b));
        assert_eq!(
            report.failures[0].error,
            SyncError::ChunkUnavailable { id: block_b }
        );
        assert!(!report.is_ok());
        assert_eq!(
            report.into_result(),
            Err(SyncError::ChunkUnavailable { id: block_b })
        );
    }

    #[tokio::test]
    async fn u_fetch_blocks_count_mismatch_reports_blockmap_disagreement() {
        let block_a = ChunkId::of_plaintext(b"a");
        let block_b = ChunkId::of_plaintext(b"b");
        let remote = Manifest::try_new(
            Seq(3),
            vec![Entry::file(
                "file",
                InodeId::from_bytes([1u8; 16]),
                0o644,
                1000,
                1000,
                2,
                7,
                &[block_a, block_b],
            )],
        )
        .expect("manifest");
        // The blockmap names one block where the manifest says two.
        let blockmap = Blockmap::new(Seq(3), vec![0], vec![block_a]).expect("blockmap");
        let plan = crate::sync::manifest::diff::plan(
            None,
            &remote,
            &TypeReplaceTree,
            ClusterId::from_bytes([1u8; 16]),
        )
        .expect("plan");
        let source = RecordingSource {
            seen: Mutex::new(Vec::new()),
            fail: None,
        };
        let report = fetch_blocks(&plan, &remote, &blockmap, &source).await;
        assert_eq!(report.failures.len(), 1);
        assert_eq!(
            report.failures[0].error,
            SyncError::Format("blockmap disagrees with manifest")
        );
        assert_eq!(
            report.into_result(),
            Err(SyncError::Format("blockmap disagrees with manifest"))
        );
    }
}
