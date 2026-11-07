//! Assembly of the relay ports a JOIN and the steady state share.
//!
//! Owner: client transport.
//!
//! The relay link and the chunk source must agree on one session, one key
//! ring and one verified cache; building them separately is how a JOIN ends
//! up with two sessions and a spent retry budget. [`RelayAssembly`] is that
//! single construction point:
//!
//! ```text
//! WELCOME.view_session ─┐
//! cluster key ring ─────┼─> RelaySyncLink ──> RelayChunkSource
//! JOINING writer ───────┘          │
//!                                  └─ rebind(control_tx) at STEADY
//! ```
//!
//! The sink is deliberately external. During JOINING it is the
//! [`ScopedHandle`](crate::client::net::scoped::ScopedHandle) of the scoped writer; at
//! STEADY it is the bounded control queue of
//! [`UplinkTask`](crate::client::net::uplink::UplinkTask). [`RelayAssembly::rebind`] swaps
//! it only after the scoped writer stopped, so one writer exists at a time.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::protocol::crypto::KeyRing;
use crate::protocol::messages::Welcome;
use crate::protocol::{Seq, SessionId};
use crate::sync::chunk::VerifiedChunkStore;
use crate::sync::manifest::Entry;
use crate::sync::{LocalTree, StateImage, StateProvider, SyncError, SyncPorts, resume};

use super::chunk_source::RelayChunkSource;
use super::sync_link::{FrameSink, RelaySyncLink};

/// The relay link plus the chunk source bound to it.
pub struct RelayAssembly {
    link: Arc<RelaySyncLink>,
    chunks: Arc<RelayChunkSource>,
}

impl fmt::Debug for RelayAssembly {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayAssembly")
            .field("link", &self.link)
            .field("chunks", &self.chunks)
            .finish()
    }
}

impl RelayAssembly {
    /// Build from an accepted `WELCOME`.
    ///
    /// The relay session is `view_session` when the server designated a
    /// holder, and a fresh id otherwise.
    pub fn new(
        welcome: &Welcome,
        sink: Arc<dyn FrameSink>,
        ring: Arc<KeyRing>,
        store: Arc<VerifiedChunkStore>,
    ) -> Self {
        Self::from_link(RelaySyncLink::from_welcome(welcome, sink, ring), store)
    }

    /// Build with an explicit session id; used by tests and reconnects.
    pub fn with_session(
        session: SessionId,
        sink: Arc<dyn FrameSink>,
        ring: Arc<KeyRing>,
        store: Arc<VerifiedChunkStore>,
    ) -> Self {
        Self::from_link(RelaySyncLink::new(sink, ring, session), store)
    }

    fn from_link(link: RelaySyncLink, store: Arc<VerifiedChunkStore>) -> Self {
        let link = Arc::new(link);
        let chunks = Arc::new(RelayChunkSource::new(Arc::clone(&link), store));
        Self { link, chunks }
    }

    /// The control plane, for `SyncPorts::link`.
    pub fn link(&self) -> Arc<RelaySyncLink> {
        Arc::clone(&self.link)
    }

    /// The content plane, for `SyncPorts::chunks`.
    pub fn chunks(&self) -> Arc<RelayChunkSource> {
        Arc::clone(&self.chunks)
    }

    /// Route later frames to the steady-state writer.
    ///
    /// Call only after [`ScopedUplink::handoff`](crate::client::net::scoped::ScopedUplink::handoff)
    /// returned, and before the steady-state `UplinkTask` starts sending.
    pub fn rebind(&self, sink: Arc<dyn FrameSink>) {
        self.link.rebind(sink);
    }
}

/// The material a JOIN needs that the CLI can build before the mount.
///
/// [`RelayAssembly`] itself cannot exist before `WELCOME`: the relay session
/// is the server's `view_session`. This type holds the stable inputs (key
/// ring, verified cache, local tree, cluster) and [`SyncAssembly::bind`]
/// creates the session-bound assembly once the accepted `WELCOME` is known.
///
/// Building the cache and the tree here, not inside the JOIN, keeps the
/// failure before the mount and gives the JOIN one store to write and one
/// tree to read.
#[derive(Debug)]
pub struct SyncAssembly {
    ring: Arc<KeyRing>,
    store: Arc<VerifiedChunkStore>,
    root: Arc<crate::store::RootFd>,
    tree: Arc<dyn LocalTree>,
    cluster: crate::protocol::crypto::ClusterId,
}

impl SyncAssembly {
    /// Bind the stable JOIN inputs.
    pub fn new(
        ring: Arc<KeyRing>,
        store: Arc<VerifiedChunkStore>,
        root: Arc<crate::store::RootFd>,
        tree: Arc<dyn LocalTree>,
        cluster: crate::protocol::crypto::ClusterId,
    ) -> Self {
        Self {
            ring,
            store,
            root,
            tree,
            cluster,
        }
    }

    /// The cluster key ring the relay link seals with.
    pub fn ring(&self) -> &Arc<KeyRing> {
        &self.ring
    }

    /// The verified cache the relay source fills.
    pub fn store(&self) -> &Arc<VerifiedChunkStore> {
        &self.store
    }

    /// The pre-mount root the holder describes.
    pub fn root(&self) -> &Arc<crate::store::RootFd> {
        &self.root
    }

    /// The local tree the diff walks.
    pub fn tree(&self) -> &Arc<dyn LocalTree> {
        &self.tree
    }

    /// The cluster the local manifest cache belongs to.
    pub const fn cluster(&self) -> crate::protocol::crypto::ClusterId {
        self.cluster
    }

    /// Create the relay assembly for `welcome`, writing through `sink`.
    ///
    /// `sink` is the JOINING scoped writer; the caller rebinds it to the
    /// steady-state control queue after the handoff.
    pub fn bind(&self, welcome: &Welcome, sink: Arc<dyn FrameSink>) -> RelayAssembly {
        RelayAssembly::new(
            welcome,
            sink,
            Arc::clone(&self.ring),
            Arc::clone(&self.store),
        )
    }

    /// Create the assembly and the [`SyncPorts`] the JOIN engine consumes.
    ///
    /// The state provider is [`JoinState`]: a manifest-only JOIN has no local
    /// state image to capture or install, so `install` refuses instead of
    /// pretending the snapshot was applied.
    pub fn ports(&self, welcome: &Welcome, sink: Arc<dyn FrameSink>) -> (RelayAssembly, SyncPorts) {
        let assembly = self.bind(welcome, sink);
        let ports = SyncPorts {
            state: Arc::new(JoinState::default()),
            chunks: Arc::clone(&assembly.chunks) as Arc<dyn crate::sync::ChunkSource>,
            link: Arc::clone(&assembly.link) as Arc<dyn crate::sync::SyncLink>,
            tree: Arc::clone(&self.tree),
            cache: Some(Arc::clone(&self.store) as Arc<dyn resume::ChunkReader>),
            delta: None,
            cluster: self.cluster,
        };
        (assembly, ports)
    }
}

/// The state provider a manifest-only JOIN exposes to the sync engine.
///
/// The JOIN has no replay state to serialize: the local tree is brought to
/// the holder's manifest by [`ClusterWins`](crate::sync::resume::ClusterWins),
/// and the replayer owns the applied watermark afterwards. Installing a
/// snapshot image is therefore refused, not silently ignored.
#[derive(Debug, Default)]
pub struct JoinState {
    applied: AtomicU64,
}

impl StateProvider for JoinState {
    fn applied_seq(&self) -> Seq {
        Seq(self.applied.load(Ordering::Relaxed))
    }

    fn capture(&self) -> Arc<dyn StateImage> {
        Arc::new(JoinImage {
            covered_seq: self.applied_seq(),
        })
    }

    fn install(&self, _covered_seq: Seq, _image: &[u8]) -> Result<(), SyncError> {
        Err(SyncError::State(
            "a manifest-only JOIN has no state image to install".to_owned(),
        ))
    }
}

#[derive(Debug)]
struct JoinImage {
    covered_seq: Seq,
}

impl StateImage for JoinImage {
    fn covered_seq(&self) -> Seq {
        self.covered_seq
    }

    fn encode(&self) -> Vec<u8> {
        Vec::new()
    }

    fn entries(&self) -> Vec<Entry> {
        Vec::new()
    }

    fn blocks(&self) -> Vec<crate::sync::chunk::ChunkId> {
        Vec::new()
    }
}
