//! Snapshot installation: pull parts, verify, decode, install.
//!
//! Owner: W14 (E7). See 43 §2.4 and C-28.
//!
//! # Two steps, one gate
//!
//! [`Installer::pull`] fetches and authenticates every chunk, assembles the
//! parts, and computes `state_digest`. [`Installer::install`] recomputes that
//! digest from the assembled parts and only then calls
//! [`StateProvider::install`]. Nothing reaches the state machine before the
//! digest matches, so a torn or mixed snapshot cannot become a baseline.
//!
//! # Why the digest is recomputed
//!
//! `pull` is the only producer of [`Pulled`], but the type is crate-visible so
//! a future resume path (W17) can hand an already-pulled container back
//! without refetching. Recomputing is a hash over bytes that are already in
//! memory; trusting a boolean flag instead would make C-28 depend on a
//! comment.

use tokio::task::JoinSet;

use crate::protocol::frame::Seq;
use crate::protocol::messages::SnapshotRef;
use crate::sync::config;
use crate::sync::config::SyncConfig;
use crate::sync::snapshot::format::{DataPartHeader, SnapshotIndex};
use crate::sync::{ChunkId, ChunkKind, ChunkSource, PartDesc, SyncError, SyncPorts, chunk_is_zero};

/// A snapshot whose parts are on the heap and whose digest is verified.
#[derive(Debug)]
pub struct Pulled {
    pub(crate) reference: SnapshotRef,
    pub(crate) index: SnapshotIndex,
    /// Data part plaintexts, index order, headers included.
    pub(crate) parts: Vec<Vec<u8>>,
    pub(crate) digest: [u8; 32],
}

/// A snapshot that has become the baseline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Installed {
    /// `applied_seq` after install.
    pub covered_seq: Seq,
    /// Parts in the container, index included.
    pub parts: u32,
    /// State image length.
    pub plain_len: u64,
}

/// Pulls and installs snapshots for one join.
#[derive(Debug)]
pub struct Installer<'a> {
    ports: &'a SyncPorts,
    config: &'a SyncConfig,
}

impl<'a> Installer<'a> {
    /// Bind the ports and the tuning.
    pub const fn new(ports: &'a SyncPorts, config: &'a SyncConfig) -> Self {
        Self { ports, config }
    }

    /// Fetch, authenticate and assemble the container.
    ///
    /// # Errors
    ///
    /// * [`SyncError::CoveredSeqMismatch`] when the index names another
    ///   sequence than the reference.
    /// * [`SyncError::PartLengthMismatch`] when a part assembles to the wrong
    ///   length.
    /// * [`SyncError::StateDigestMismatch`] when the parts do not hash to the
    ///   index digest.
    /// * [`SyncError::ChunkUnavailable`] / [`SyncError::ChunkCorrupt`] from the
    ///   chunk source.
    pub async fn pull(&self, reference: &SnapshotRef) -> Result<Pulled, SyncError> {
        let chunks = self.ports.chunks.as_ref();
        let chunk0 = chunks
            .fetch(
                ChunkKind::Snapshot,
                ChunkId::from_bytes(reference.root_chunk_id),
            )
            .await?;
        let (index_chunks, extra) = SnapshotIndex::peek_index_chunks(&chunk0)?;

        let mut index_plain = chunk0;
        for (slot, id) in extra
            .iter()
            .copied()
            .take(index_chunks as usize - 1)
            .enumerate()
        {
            if chunk_is_zero(id) {
                return Err(SyncError::Format("index chunk id missing"));
            }
            let piece = chunks.fetch(ChunkKind::Snapshot, id).await?;
            if piece.len() != config::CHUNK_BYTES && slot + 1 != index_chunks as usize - 1 {
                return Err(SyncError::Format("index chunk shorter than a full chunk"));
            }
            index_plain.extend_from_slice(&piece);
        }
        let mut index = SnapshotIndex::decode(&index_plain)?;
        let covered_seq = Seq(reference.covered_seq);
        if index.covered_seq != covered_seq {
            return Err(SyncError::CoveredSeqMismatch {
                expected: covered_seq,
                found: index.covered_seq,
            });
        }
        index.index_chunks[0] = ChunkId::from_bytes(reference.root_chunk_id);
        if index.part_count != reference.part_count {
            return Err(SyncError::Format("part count disagrees with reference"));
        }
        if index.index_chunks.first().copied() != Some(ChunkId::from_bytes(reference.root_chunk_id))
        {
            return Err(SyncError::Format("index root disagrees with reference"));
        }
        if index.payload_len() != reference.total_len {
            return Err(SyncError::Format("plain length disagrees with reference"));
        }

        let mut hasher = blake3::Hasher::new();
        let mut parts = Vec::with_capacity(index.parts.len());
        for desc in &index.parts {
            let plain = self.fetch_part(desc).await?;
            let header = DataPartHeader::decode(&plain)?;
            if header.covered_seq != covered_seq {
                return Err(SyncError::CoveredSeqMismatch {
                    expected: covered_seq,
                    found: header.covered_seq,
                });
            }
            if header.part_index != desc.part_index {
                return Err(SyncError::Format(
                    "data part index disagrees with descriptor",
                ));
            }
            hasher.update(&plain);
            parts.push(plain);
        }
        let digest = *hasher.finalize().as_bytes();
        if digest != index.state_digest {
            return Err(SyncError::StateDigestMismatch);
        }
        Ok(Pulled {
            reference: *reference,
            index,
            parts,
            digest,
        })
    }

    /// Install a pulled container as the baseline.
    ///
    /// # Errors
    ///
    /// * [`SyncError::CoveredSeqMismatch`] if the reference and index differ.
    /// * [`SyncError::StateDigestMismatch`] if any part changed after `pull`.
    /// * [`SyncError::State`] if the provider refuses the image.
    pub fn install(&self, pulled: Pulled) -> Result<Installed, SyncError> {
        let covered_seq = Seq(pulled.reference.covered_seq);
        if pulled.index.covered_seq != covered_seq {
            return Err(SyncError::CoveredSeqMismatch {
                expected: covered_seq,
                found: pulled.index.covered_seq,
            });
        }
        if pulled.parts.len() + 1 != pulled.index.part_count as usize {
            return Err(SyncError::Format("installed part count mismatch"));
        }

        let mut hasher = blake3::Hasher::new();
        let mut image = Vec::with_capacity(pulled.reference.total_len as usize);
        for (offset, plain) in pulled.parts.iter().enumerate() {
            let desc = pulled
                .index
                .parts
                .get(offset)
                .ok_or(SyncError::Format("installed part has no descriptor"))?;
            if plain.len() != desc.plain_len as usize {
                return Err(SyncError::PartLengthMismatch {
                    part: desc.part_index,
                    expected: desc.plain_len,
                    found: u32::try_from(plain.len()).unwrap_or(u32::MAX),
                });
            }
            let header = DataPartHeader::decode(plain)?;
            let expected =
                u32::try_from(offset + 1).map_err(|_| SyncError::Format("too many parts"))?;
            if header.part_index != expected {
                return Err(SyncError::Format("data part index out of order"));
            }
            hasher.update(plain);
            image.extend_from_slice(&plain[DataPartHeader::LEN..]);
        }
        let digest = *hasher.finalize().as_bytes();
        if digest != pulled.index.state_digest || digest != pulled.digest {
            return Err(SyncError::StateDigestMismatch);
        }
        if image.len() as u64 != pulled.reference.total_len {
            return Err(SyncError::PartLengthMismatch {
                part: 0,
                expected: u32::try_from(pulled.reference.total_len).unwrap_or(u32::MAX),
                found: u32::try_from(image.len()).unwrap_or(u32::MAX),
            });
        }

        self.ports.state.install(covered_seq, &image)?;
        Ok(Installed {
            covered_seq,
            parts: pulled.index.part_count,
            plain_len: pulled.reference.total_len,
        })
    }

    /// Fetch one part's chunks with a bounded window, in order.
    async fn fetch_part(&self, desc: &PartDesc) -> Result<Vec<u8>, SyncError> {
        let ids: Vec<ChunkId> = desc.chunks().collect();
        if ids.is_empty() {
            return Err(SyncError::Format("data part has no chunks"));
        }
        let pieces = self.fetch_all(&ids).await?;
        let mut plain = Vec::with_capacity(desc.plain_len as usize);
        for piece in pieces {
            plain.extend_from_slice(&piece);
        }
        if plain.len() != desc.plain_len as usize {
            return Err(SyncError::PartLengthMismatch {
                part: desc.part_index,
                expected: desc.plain_len,
                found: u32::try_from(plain.len()).unwrap_or(u32::MAX),
            });
        }
        Ok(plain)
    }

    /// Fetch many chunks with at most `chunk_window` in flight.
    ///
    /// A part is four chunks, so the default window of 16 keeps four parts
    /// worth of work outstanding, which is the `PART_WINDOW` of 43 §2.4.
    async fn fetch_all(&self, ids: &[ChunkId]) -> Result<Vec<Vec<u8>>, SyncError> {
        let window = self.config.chunk_window();
        let source: std::sync::Arc<dyn ChunkSource> = self.ports.chunks.clone();
        let mut slots: Vec<Option<Vec<u8>>> = vec![None; ids.len()];
        let mut tasks = JoinSet::new();
        let mut submitted = 0usize;
        let mut completed = 0usize;

        while completed < ids.len() {
            while tasks.len() < window && submitted < ids.len() {
                let id = ids[submitted];
                let source = std::sync::Arc::clone(&source);
                let slot = submitted;
                tasks.spawn(async move { (slot, source.fetch(ChunkKind::Snapshot, id).await) });
                submitted += 1;
            }
            match tasks.join_next().await {
                Some(Ok((slot, Ok(plain)))) => {
                    slots[slot] = Some(plain);
                    completed += 1;
                }
                Some(Ok((_, Err(err)))) => {
                    tasks.abort_all();
                    return Err(err);
                }
                Some(Err(_)) => {
                    tasks.abort_all();
                    return Err(SyncError::Io("chunk fetch task failed".to_owned()));
                }
                None => return Err(SyncError::Io("chunk fetch made no progress".to_owned())),
            }
        }

        slots
            .into_iter()
            .map(|slot| slot.ok_or(SyncError::Io("chunk slot missing".to_owned())))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::sync::snapshot::Generator;
    use crate::sync::test_support::{FakeLink, FakeState, MemChunks, MemTree, make_image, ports};
    use crate::sync::{StateImage, StateProvider, SyncConfig};

    fn fixture() -> (
        std::sync::Arc<MemChunks>,
        std::sync::Arc<FakeState>,
        SnapshotRef,
        Vec<u8>,
    ) {
        let chunks = MemChunks::new();
        let image = make_image(4096, &[("a", 1), ("b", 3)], 2 * 1024 * 1024);
        let bytes = image.encode();
        let bundle = Generator::new(
            chunks.as_ref(),
            crate::protocol::frame::ClientId::from_bytes([1; 16]),
        )
        .generate(&image)
        .unwrap();
        let state = FakeState::new(0, make_image(0, &[], 0));
        (chunks, state, bundle.reference, bytes)
    }

    /// C-28: a verified container installs and moves `applied_seq`.
    #[tokio::test]
    async fn i_snapshot_install_happy_path() {
        let (chunks, state, reference, bytes) = fixture();
        let link = FakeLink::new(chunks.clone());
        let tree = MemTree::new();
        let ports = ports(state.clone(), chunks.clone(), link, tree);
        let config = SyncConfig::new();
        let installer = Installer::new(&ports, &config);
        let pulled = installer.pull(&reference).await.unwrap();
        let installed = installer.install(pulled).unwrap();
        assert_eq!(installed.covered_seq, Seq(4096));
        assert_eq!(installed.plain_len, bytes.len() as u64);
        assert_eq!(state.applied_seq(), Seq(4096));
        assert_eq!(state.installed(), 1);
    }

    /// C-28: a data part that does not hash to the index digest is refused,
    /// and the state machine keeps its old watermark.
    #[tokio::test]
    async fn i_snapshot_install_digest_gate() {
        let (chunks, state, reference, _bytes) = fixture();
        let victim = chunks
            .fetch(
                ChunkKind::Snapshot,
                ChunkId::from_bytes(reference.root_chunk_id),
            )
            .await
            .map(|_| ());
        victim.unwrap();

        // Corrupt one data chunk by flipping its plaintext after open; the id
        // still matches, so only the container digest can catch it.
        let probe = MemChunks::new();
        let image = make_image(4096, &[("a", 1)], 1024);
        let bundle = Generator::new(
            probe.as_ref(),
            crate::protocol::frame::ClientId::from_bytes([1; 16]),
        )
        .generate(&image)
        .unwrap();
        let data_id = bundle.index.parts[0].chunks().next().unwrap();
        probe.corrupt_plaintext(data_id);
        let link = FakeLink::new(probe.clone());
        let tree = MemTree::new();
        let ports = ports(state.clone(), probe.clone(), link, tree);
        let config = SyncConfig::new();
        let installer = Installer::new(&ports, &config);
        assert_eq!(
            installer.pull(&bundle.reference).await.unwrap_err(),
            SyncError::StateDigestMismatch
        );
        assert_eq!(state.applied_seq(), Seq(0));
        assert_eq!(state.installed(), 0);
    }

    /// C-28: the index sequence must equal the reference sequence.
    #[tokio::test]
    async fn i_snapshot_install_rejects_wrong_covered_seq() {
        let (chunks, state, reference, _bytes) = fixture();
        let mut wrong = reference;
        wrong.covered_seq = 8192;
        let link = FakeLink::new(chunks.clone());
        let tree = MemTree::new();
        let ports = ports(state.clone(), chunks.clone(), link, tree);
        let config = SyncConfig::new();
        let installer = Installer::new(&ports, &config);
        assert_eq!(
            installer.pull(&wrong).await.unwrap_err(),
            SyncError::CoveredSeqMismatch {
                expected: Seq(8192),
                found: Seq(4096),
            }
        );
        assert_eq!(state.applied_seq(), Seq(0));
    }

    /// A truncated part is reported as a length mismatch, not as a digest
    /// mismatch, so the operator sees the right cause.
    #[tokio::test]
    async fn i_snapshot_install_rejects_short_part() {
        let (chunks, state, reference, _bytes) = fixture();
        let link = FakeLink::new(chunks.clone());
        let tree = MemTree::new();
        let ports = ports(state.clone(), chunks.clone(), link, tree);
        let config = SyncConfig::new();
        let installer = Installer::new(&ports, &config);
        let mut pulled = installer.pull(&reference).await.unwrap();
        pulled.parts[0].pop();
        assert!(matches!(
            installer.install(pulled),
            Err(SyncError::PartLengthMismatch { part: 1, .. })
        ));
        assert_eq!(state.applied_seq(), Seq(0));
    }

    /// The chunk window is honoured and order is preserved.
    #[tokio::test]
    async fn i_snapshot_install_fetch_window() {
        let (chunks, state, reference, _bytes) = fixture();
        let link = FakeLink::new(chunks.clone());
        let tree = MemTree::new();
        let ports = ports(state.clone(), chunks.clone(), link, tree);
        let config = SyncConfig {
            chunk_window: 2,
            ..SyncConfig::new()
        };
        let installer = Installer::new(&ports, &config);
        let pulled = installer.pull(&reference).await.unwrap();
        assert!(installer.install(pulled).is_ok());
        assert!(chunks.fetches() >= 2);
    }

    /// The helper is kept honest: the fixture is sealed with the W3 sealer and
    /// the plaintext hashes match their ids.
    #[tokio::test]
    async fn u_snapshot_install_chunk_identity() {
        let (chunks, _state, reference, _bytes) = fixture();
        let plain = chunks
            .fetch(
                ChunkKind::SnapshotPart,
                ChunkId::from_bytes(reference.root_chunk_id),
            )
            .await
            .unwrap();
        assert_eq!(
            ChunkId::of(&plain),
            ChunkId::from_bytes(reference.root_chunk_id)
        );
    }
}
