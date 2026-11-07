//! Client actor: outbox/coalescer, deterministic replayer, lifecycle, status,
//! uplink/downlink connections.
//!
//! Owner: W11/W12 (E5). See 41, 51 §4 and 53 W11/W12.
//!
//! | module | responsibility | owner |
//! |---|---|---|
//! | [`config`] | endpoint, mountpoint, identity, tuning | W11 |
//! | [`writer`] | bounded outbox and write coalescer | W11 |
//! | [`replayer`] | `S(seq)`, pending overlay, dedup, reorder | W11 |
//! | [`status`] | status document, counters, connection trace | W11 |
//! | [`lifecycle`] | pure state machine, write gate, exit codes | W12 |
//! | [`net`] | dual HTTP streams, HELLO/WELCOME, downlink routing | W12 |
//!
//! `client` never depends on `fuse`; [`Client::run`] is the only assembly
//! point and keeps the FUSE adapter behind the `fuse` feature.

pub mod assembly;
pub mod chunk_source;
pub mod config;
pub mod lifecycle;
pub mod net;
pub mod replayer;
pub mod status;
pub mod sync_link;
pub mod writer;

pub use assembly::{RelayAssembly, SyncAssembly};
pub use chunk_source::{RelayChunkSource, fetch_blocks};
pub use config::{Config, Endpoint, InstanceId, PasswordSource, Scheme, Tuning};
pub use lifecycle::{
    Action, Cause, Event, FatalError, JoinError, JoinOutcome, JoinRetryPolicy, Lifecycle,
    MountError, Reason, ResyncReason, Sig, State, WriteGate,
};
pub use net::{
    Conn, ConnError, ConnOptions, ConnParts, DataCache, Downlink, DownlinkError, DownlinkHandle,
    DownlinkItem, DownlinkOutcome, Uplink, UplinkError, UplinkTask, decode_ordered,
};
pub use replayer::{
    IncomingOp, Op, OpAttrs, OpBody, OpData, PendingOverlay, ReplayBacking, Replayer, SyncHandle,
};
pub use sync_link::{FrameSink, RelayError, RelaySyncLink};
pub use writer::{Backpressure, LocalOp, LocalSeq, Outbox, OutboxDepth, QueuedOp, Span};

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::client::net::Holder;
use crate::client::net::downlink::decode_ordered_verified;
use crate::client::net::join_proof::JoinProofResponder;
use crate::client::net::scoped::ScopedUplink;
use crate::client::status::{Conntrace, Counters, ReplayStatus, StatusSnapshot, StatusWriter};
use crate::crypto::proof::Proof;
use crate::crypto::secret::MasterKey;
use crate::crypto::sign::SigningKey;
use crate::protocol::crypto::{ClusterId, KeyRing, NonceMinter, Opener, Sealer};
use crate::protocol::identity::{
    Identity, KeyAnnounce, KeyDirectory, KeyEpoch, MemoryIdentity, PublicKey, Signature,
};
use crate::protocol::messages::{RelaySub, WcpWriter, Welcome, fid};
use crate::protocol::{
    Caps, ClientId, Flags, FrameBuf, FrameDecoder, FrameHeader, Hello, Limits, Message, MsgType,
    Prefix, ProtoVersion, RoutePrefix, Seq, SessionId, StreamId, TrnReason, decode_plain,
    decode_sealed,
};
use crate::store::runtime_dir::RuntimeDir;
use crate::store::{AttrDelta, BackingStore, Errno, InodeId, Kind, PosixBacking, RenameFlags};
use crate::store::{NodeTable, RootFd};
use crate::sync::baseline::FsTree;
use crate::sync::chunk::VerifiedChunkStore;
use crate::sync::manifest::{Blockmap, LocalManifest, Manifest, ManifestService};
use crate::sync::rsync::OxideEngine;
use crate::sync::{
    ChunkId, ChunkKind, ChunkReader, ClusterWins, DeltaPeer, DiffCounts, DiskTree, JoinView,
    LocalTree, RemoteView, SyncConfig, SyncError, SyncPorts,
};
use crate::transport::{DialOptions, EventsStream, Transport};

/// Why [`Client::run`] could not start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The configuration could not be used.
    #[error("configuration: {0}")]
    Config(#[from] config::ConfigError),
    /// The runtime directory or single-instance lock failed.
    #[error("runtime directory: {0}")]
    Runtime(#[from] Errno),
    /// The transport endpoint could not be parsed.
    #[error("endpoint: {0}")]
    Endpoint(#[from] crate::transport::EndpointError),
    /// The transport could not be dialled or handshaken.
    #[error("connection: {0}")]
    Connection(#[from] ConnError),
    /// FUSE is not compiled in.
    #[error("this build has no FUSE support")]
    FuseDisabled,
    /// A local I/O operation failed.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    /// A runtime task could not be started.
    #[error("runtime task failed: {0}")]
    Task(String),
    /// The sync core refused the join.
    #[error("sync: {0}")]
    Sync(#[from] SyncError),
    /// The join cannot proceed without a remote view.
    #[error("join: {0}")]
    Join(String),
}

/// What the cluster-wins step did during a JOIN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinReport {
    /// Sequence the applied manifest names.
    pub at_seq: Seq,
    /// Watermark of the remote view, i.e. the replayer's starting point.
    ///
    /// With a `WELCOME` that declares `view_seq`, this is that value after
    /// checking it equals `current_seq` and the view's own watermark. With no
    /// declaration it is the watermark of the view the client built: the
    /// snapshot manifest, the injected [`JoinView`], or `current_seq` for an
    /// explicitly accepted empty view.
    pub view_seq: Seq,
    /// The manifest the JOIN installed.
    ///
    /// The replayer rebuilds its namespace from this view before the first
    /// frame; keeping it here makes the exact view the disk was brought to
    /// inspectable after the JOIN.
    pub manifest: Manifest,
    /// Per-class counts from the diff.
    pub counts: DiffCounts,
    /// `LocalOnly` entries removed.
    pub removed: u64,
    /// Items replaced through trash.
    pub replaced: u64,
    /// Staged files installed.
    pub installed: u64,
    /// Directories created.
    pub dirs: u64,
    /// In-place attribute changes.
    pub attrs: u64,
    /// Symlinks created.
    pub symlinks: u64,
    /// Watermark installed by the snapshot, when one was pulled.
    pub covered_seq: Option<Seq>,
}

/// Shared replay/watermark values rendered into the status document.
///
/// `applied` and `epoch` are also the watermark every `PING` reports, so they
/// are `Arc` handles the uplink can clone without borrowing the replayer.
#[derive(Debug, Default)]
struct StatusState {
    applied: Arc<AtomicU64>,
    epoch: Arc<AtomicU64>,
    pending: AtomicU64,
    reorder: AtomicU64,
    dedup: AtomicU64,
    resyncs: AtomicU64,
    diverged: AtomicBool,
}

impl StatusState {
    /// Hand the uplink a live view of the watermark.
    fn watermark(&self) -> net::WatermarkReader {
        net::WatermarkReader::new(Arc::clone(&self.applied), Arc::clone(&self.epoch))
    }

    fn publish(&self, replayer: &Replayer) {
        self.applied
            .store(replayer.applied().get(), Ordering::Relaxed);
        self.epoch.store(replayer.epoch(), Ordering::Relaxed);
        self.pending
            .store(replayer.pending().len() as u64, Ordering::Relaxed);
        self.reorder
            .store(replayer.reorder_len() as u64, Ordering::Relaxed);
        self.dedup
            .store(replayer.dedup_len() as u64, Ordering::Relaxed);
        self.resyncs
            .store(u64::from(replayer.resync_count()), Ordering::Relaxed);
        self.diverged
            .store(replayer.read_state().diverged(), Ordering::Relaxed);
    }

    fn replay(&self) -> ReplayStatus {
        ReplayStatus {
            pending: self.pending.load(Ordering::Relaxed),
            reorder: self.reorder.load(Ordering::Relaxed),
            dedup: self.dedup.load(Ordering::Relaxed),
            resyncs: u32::try_from(self.resyncs.load(Ordering::Relaxed)).unwrap_or(u32::MAX),
            diverged: self.diverged.load(Ordering::Relaxed),
        }
    }
}

/// Write one status document. Failure is logged, never fatal: the status
/// file is an observer, not part of the data path.
fn write_status(writer: &Option<StatusWriter>, client: &Client, state: &StatusState) {
    let Some(writer) = writer else {
        return;
    };
    let snapshot = StatusSnapshot::new(
        client.config.mount_id.as_str(),
        client.state().as_str(),
        Seq(state.applied.load(Ordering::Relaxed)),
        state.epoch.load(Ordering::Relaxed),
    )
    .with_outbox(client.outbox().depth().into())
    .with_replay(state.replay())
    .with_counters(client.counters().snapshot())
    .with_conntrace(client.conntrace().snapshot());
    if let Err(error) = writer.write(&snapshot) {
        tracing::warn!(%error, "status write failed");
    }
}

/// Default deadline for the JOIN_PROOF verdict.
///
/// A member answers in one round trip; the bound keeps a cluster with no
/// online verifier from stalling the mount.
pub const JOIN_PROOF_TIMEOUT: Duration = Duration::from_secs(2);

/// Result code carried by `RELAY{CTRL, JOIN_FAIL}` in `F_PROOF_RESULT`.
pub const PROOF_RESULT_INVALID: u8 = 1;

/// The `F_PROOF` did not open: the sender does not hold the cluster key, or
/// the proof was tampered with.
pub const PROOF_RESULT_PROOF_INVALID: u8 = 2;

/// The proof and the accompanying key entry describe different keys.
pub const PROOF_RESULT_KEY_MISMATCH: u8 = 3;

/// The key entry did not pass the self-certification or self-signature check.
pub const PROOF_RESULT_KEY_REJECTED: u8 = 4;

/// Fixed width of one `F_KEY_ENTRIES` record:
/// `client_id 16 ‖ key_epoch u32 LE ‖ public_key 32 ‖ self_sig 64`.
pub const KEY_ENTRY_LEN: usize = ClientId::LEN + 4 + PublicKey::LEN + Signature::LEN;

/// Cluster credentials for the JOIN_PROOF exchange (50 §3.2).
///
/// The proof binds this client's `client_id` to its Ed25519 key inside a
/// PSK-sealed `RELAY{CTRL, JOIN_PROOF}`; a member opens it, answers
/// `JOIN_ACCEPT` with the keys it knows, and a proof that does not open is
/// never answered. Without this configuration the JOIN runs as before and the
/// receive path cannot verify authorship — the pre-W22 behaviour recorded as
/// the F16 known gap.
pub struct JoinAuth {
    master: Arc<MasterKey>,
    signing: Arc<SigningKey>,
    /// Nonce source for the sealed proof and its answer. One per client keeps
    /// the (instance, counter) pair unique across every frame it seals.
    nonces: Mutex<NonceMinter>,
}

impl JoinAuth {
    /// Bind the cluster key and this client's signing key.
    pub fn new(master: Arc<MasterKey>, signing: Arc<SigningKey>) -> Self {
        Self {
            master,
            signing,
            nonces: Mutex::new(NonceMinter::with_instance(rand::random::<u64>())),
        }
    }

    /// This client's signing key.
    pub fn signing(&self) -> &Arc<SigningKey> {
        &self.signing
    }

    /// The cluster master key the proof is sealed with.
    pub(crate) fn master(&self) -> &Arc<MasterKey> {
        &self.master
    }

    fn nonces(&self) -> std::sync::MutexGuard<'_, NonceMinter> {
        self.nonces.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl std::fmt::Debug for JoinAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JoinAuth")
            .field("client_id", &self.signing.client_id())
            .field("key_epoch", &self.signing.key_epoch())
            .finish_non_exhaustive()
    }
}

/// What the replay pump needs to authenticate peers and answer join proofs.
struct VerifyContext {
    auth: Arc<JoinAuth>,
    keys: Arc<Mutex<KeyDirectory>>,
    cluster: ClusterId,
    /// Raw control frames for the uplink task, the only RPC writer.
    control: mpsc::Sender<FrameBuf>,
}

/// Verdict of the JOIN_PROOF exchange.
enum JoinVerdict {
    /// A member verified the proof and sent the keys it knows.
    Accepted(Vec<KeyAnnounce>),
    /// A member refused the proof; `F_PROOF_RESULT` carries the reason.
    Rejected(u8),
    /// The server reported no peer: no member is online, or this is the
    /// first client.
    NoVerifier,
    /// A member was online but did not answer within the deadline.
    NoAnswer,
}

/// Client-owned state assembled before the mount.
///
/// The fields are deliberately independent:
///
/// * [`Outbox`] is the admission gate the FUSE write path will use (W13b);
/// * [`PendingOverlay`] is the optimistic layer shared with the replayer;
/// * [`Replayer`] is created after `WELCOME`, because only then are the epoch
///   and the JOIN watermark known;
/// * [`WriteGate`] mirrors [`Lifecycle::state`] for lock-free FUSE checks.
#[derive(Debug)]
pub struct Client {
    config: Config,
    /// Mount with `allow_other` (`SessionACL::All`) instead of the default
    /// owner-and-root ACL.
    allow_other: bool,
    lifecycle: Lifecycle,
    gate: Arc<WriteGate>,
    outbox: Arc<Outbox>,
    pending: Arc<PendingOverlay>,
    /// Replay-backlog window shared by the outbox and the replayer.
    backpressure: Arc<Backpressure>,
    /// Shared with the FUSE write path; attached to the replayer at JOIN.
    sync: SyncHandle,
    counters: Arc<Counters>,
    conntrace: Arc<Conntrace>,
    replayer: Option<Replayer>,
    limits: Limits,
    handshake_timeout: Duration,
    downlink_depth: usize,
    /// Root descriptor opened before the mount (43 I13). A JOIN must use it,
    /// never re-resolve the mountpoint through FUSE.
    root: Option<Arc<RootFd>>,
    /// Cluster identity for the local manifest cache.
    cluster: Option<ClusterId>,
    /// Remote view supplied by the assembly layer (W14/W16 transport).
    join_view: Option<Arc<dyn JoinView>>,
    /// Stable relay inputs assembled before the mount (CLI production path).
    sync_assembly: Option<SyncAssembly>,
    /// Build [`Client::sync_assembly`] from the mounted root at JOIN time.
    relay_enabled: bool,
    /// Cluster key ring for the relay assembly (production `run` path).
    relay_ring: Option<Arc<KeyRing>>,
    /// Relay link bound to the `WELCOME` of the current JOIN.
    relay: Option<Arc<RelayAssembly>>,
    /// Holder that answers other clients' relay requests from this tree.
    holder: Option<Arc<Holder>>,
    /// Sync ports used to pull a snapshot and its manifest.
    sync_ports: Option<SyncPorts>,
    /// Result of the last cluster-wins step.
    last_join: Option<JoinReport>,
    /// Cluster credentials for the JOIN_PROOF exchange.
    join_auth: Option<Arc<JoinAuth>>,
    /// Public keys learned from `JOIN_PROOF`/`JOIN_ACCEPT`; the receive path
    /// verifies every `ORDERED` against this directory.
    keys: Arc<Mutex<KeyDirectory>>,
    /// Deadline for the JOIN_PROOF verdict.
    join_proof_timeout: Duration,
    /// Frames read while waiting for the verdict, in arrival order.
    join_backlog: Vec<FrameBuf>,
}

impl Client {
    /// Assemble the client from a validated configuration.
    ///
    /// No socket is opened and no file is touched. [`Client::run`] performs
    /// the lifecycle I/O.
    pub fn new(config: Config) -> Self {
        let tuning = config.tuning;
        let backpressure = Arc::new(Backpressure::default_window());
        Self {
            config,
            allow_other: false,
            lifecycle: Lifecycle::new(),
            gate: Arc::new(WriteGate::new(State::Boot)),
            outbox: Arc::new(
                Outbox::with_tuning(&tuning).with_backpressure(Arc::clone(&backpressure)),
            ),
            pending: Arc::new(PendingOverlay::new()),
            backpressure,
            sync: SyncHandle::new(),
            counters: Arc::new(Counters::default()),
            conntrace: Arc::new(Conntrace::default()),
            replayer: None,
            limits: Limits::default(),
            handshake_timeout: net::conn::HANDSHAKE_TIMEOUT,
            downlink_depth: net::DEFAULT_DOWNLINK_DEPTH,
            root: None,
            cluster: None,
            join_view: None,
            sync_assembly: None,
            relay_enabled: false,
            relay_ring: None,
            relay: None,
            holder: None,
            sync_ports: None,
            last_join: None,
            join_auth: None,
            keys: Arc::new(Mutex::new(KeyDirectory::new(ClusterId::from_bytes(
                [0u8; 16],
            )))),
            join_proof_timeout: JOIN_PROOF_TIMEOUT,
            join_backlog: Vec::new(),
        }
    }

    /// Configuration.
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Mount with `allow_other`; requires `user_allow_other` in
    /// `/etc/fuse.conf` and is checked by the CLI before this builder runs.
    pub fn with_allow_other(mut self, allow_other: bool) -> Self {
        self.allow_other = allow_other;
        self
    }

    /// Current lifecycle state.
    pub const fn state(&self) -> State {
        self.lifecycle.state()
    }

    /// The write gate shared with the FUSE callbacks.
    pub fn gate(&self) -> &WriteGate {
        self.gate.as_ref()
    }

    /// A shared handle to the write gate.
    ///
    /// The FUSE adapter is mounted before [`Client::join`] runs and must
    /// observe every later lifecycle transition, so it holds the same
    /// allocation rather than a copy.
    pub fn gate_handle(&self) -> Arc<WriteGate> {
        Arc::clone(&self.gate)
    }

    /// The outbox shared with the FUSE write path.
    pub const fn outbox(&self) -> &Arc<Outbox> {
        &self.outbox
    }

    /// The pending overlay shared with the replayer and FUSE.
    pub const fn pending(&self) -> &Arc<PendingOverlay> {
        &self.pending
    }

    /// The handle the FUSE write path waits on and reads locks through.
    pub fn sync(&self) -> &SyncHandle {
        &self.sync
    }

    /// Shared counters for the status document.
    pub const fn counters(&self) -> &Arc<Counters> {
        &self.counters
    }

    /// Shared connection trace for the status document.
    pub const fn conntrace(&self) -> &Arc<Conntrace> {
        &self.conntrace
    }

    /// The replay engine, once a JOIN completed.
    pub const fn replayer(&self) -> Option<&Replayer> {
        self.replayer.as_ref()
    }

    /// Take the replay engine (tests and the replay pump).
    pub fn take_replayer(&mut self) -> Option<Replayer> {
        self.replayer.take()
    }

    /// What the last JOIN's cluster-wins step did.
    pub const fn last_join(&self) -> Option<&JoinReport> {
        self.last_join.as_ref()
    }

    /// Set the cluster identity used for the local manifest cache.
    pub fn with_cluster(mut self, cluster: ClusterId) -> Self {
        self.cluster = Some(cluster);
        self.keys = Arc::new(Mutex::new(KeyDirectory::new(cluster)));
        self
    }

    /// Supply the cluster key and this client's signing key for `JOIN_PROOF`.
    ///
    /// With this set, [`Client::join`] sends a sealed proof and waits for a
    /// member's `JOIN_ACCEPT`, and the receive path verifies every `ORDERED`
    /// signature against the keys learned from the exchange. The key directory
    /// starts with this client's own entry, so a client always verifies the
    /// echo of its own operations.
    pub fn with_join_auth(mut self, master: Arc<MasterKey>, signing: Arc<SigningKey>) -> Self {
        self.join_auth = Some(Arc::new(JoinAuth::new(master, signing)));
        self
    }

    /// Override the JOIN_PROOF verdict deadline.
    pub fn with_join_proof_timeout(mut self, timeout: Duration) -> Self {
        self.join_proof_timeout = timeout.max(Duration::from_millis(1));
        self
    }

    /// The public keys this client will verify operations against.
    pub fn keys(&self) -> &Arc<Mutex<KeyDirectory>> {
        &self.keys
    }

    /// Frames read while waiting for the JOIN verdict, in arrival order.
    ///
    /// The caller hands them to [`Downlink::with_backlog`] before running the
    /// loop, so no frame read during the handshake is lost.
    pub fn take_join_backlog(&mut self) -> Vec<FrameBuf> {
        std::mem::take(&mut self.join_backlog)
    }

    /// Supply the remote view for a JOIN against a non-empty cluster.
    ///
    /// Without a view the JOIN falls back to the empty manifest at the
    /// server watermark, as described on [`Client::join`].
    pub fn with_join_view(mut self, view: Arc<dyn JoinView>) -> Self {
        self.join_view = Some(view);
        self
    }

    /// Supply the W14/W16 ports used to pull a snapshot and its manifest.
    ///
    /// When `WELCOME` carries a snapshot and these ports are present, the JOIN
    /// installs the snapshot through W14's [`Installer`] and pulls the manifest
    /// through [`ManifestService`] before the local diff runs. The apply stage
    /// reads content from `ports.cache`.
    pub fn with_sync_ports(mut self, ports: SyncPorts) -> Self {
        self.sync_ports = Some(ports);
        self
    }

    /// Supply the relay material the production JOIN uses.
    ///
    /// The CLI builds the verified cache and the local tree before the mount
    /// and passes them here. [`Client::join_with_ring`] binds them to the
    /// accepted `WELCOME`, writes JOINING relay requests through a scoped
    /// uplink and keeps the same link for the steady state.
    pub fn with_sync_assembly(mut self, assembly: SyncAssembly) -> Self {
        self.sync_assembly = Some(assembly);
        self
    }

    /// Build the relay assembly from the mounted root when the JOIN starts.
    ///
    /// The CLI enables this instead of opening a root descriptor before the
    /// lifecycle's stale-mount cleanup: `mount_fuse` opens the root after the
    /// cleanup, and [`Client::prepare_relay`] binds the cache and tree to that
    /// descriptor. A pre-cleanup descriptor could point at a stale mount.
    pub fn with_relay(mut self, enabled: bool) -> Self {
        self.relay_enabled = enabled;
        self
    }

    /// Take the relay link the last JOIN bound to its `WELCOME`.
    ///
    /// The steady-state driver rebinds it to the control queue and passes it
    /// to the replay pump. `None` means this JOIN used an injected view or an
    /// empty cluster.
    pub(crate) fn take_relay(&mut self) -> Option<Arc<RelayAssembly>> {
        self.relay.take()
    }

    /// Build the relay assembly from the mounted root.
    ///
    /// The root descriptor comes from `mount_fuse`, which runs after the
    /// lifecycle's stale-mount cleanup. Opening it earlier could capture a
    /// stale mount at the same path.
    fn prepare_relay(&mut self) -> Result<(), ClientError> {
        if !self.relay_enabled || self.sync_assembly.is_some() {
            return Ok(());
        }
        let root = self
            .root
            .as_ref()
            .ok_or_else(|| ClientError::Join("relay JOIN needs the mounted root".to_owned()))?;
        let ring = self
            .relay_ring
            .as_ref()
            .ok_or_else(|| ClientError::Join("relay JOIN needs the cluster key ring".to_owned()))?;
        let cluster = self
            .cluster
            .unwrap_or_else(|| ClusterId::from_bytes([0u8; 16]));
        let store = Arc::new(
            VerifiedChunkStore::open(Arc::clone(root), chunk_cache_key(ring.as_ref()))
                .map_err(|error| ClientError::Join(format!("verified chunk cache: {error}")))?,
        );
        let tree: Arc<dyn LocalTree> = Arc::new(FsTree::new(Arc::clone(root), cluster));
        self.sync_assembly = Some(SyncAssembly::new(
            Arc::clone(ring),
            store,
            Arc::clone(root),
            tree,
            cluster,
        ));
        Ok(())
    }

    /// Override the handshake deadline (tests, slow links).
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Override the ORDERED channel depth.
    pub fn with_downlink_depth(mut self, depth: usize) -> Self {
        self.downlink_depth = depth.max(1);
        self
    }

    /// Apply one lifecycle event and publish the resulting state to the gate.
    ///
    /// This is the only place where the gate changes, so the FUSE side can
    /// never observe a state the lifecycle has not entered.
    pub fn on(&mut self, event: Event) -> Vec<Action> {
        let actions = self.lifecycle.on(event);
        self.gate.set(self.lifecycle.state());
        actions
    }

    /// Build the transport endpoint from the client configuration.
    pub fn transport_endpoint(&self) -> Result<crate::transport::Endpoint, ClientError> {
        let url = format!(
            "{}{}",
            self.config.endpoint.origin(),
            self.config.endpoint.prefix
        );
        Ok(crate::transport::Endpoint::parse(&url)?)
    }

    /// Dial, send `HELLO`, accept `WELCOME`, and run the JOIN's local phase.
    ///
    /// The JOIN is cluster-wins (39 §2.6). When `WELCOME` names a snapshot and
    /// [`Client::with_sync_ports`] supplied the W14/W16 ports, the snapshot is
    /// pulled and installed and the manifest is fetched; the local diff then
    /// deletes local-only paths and replaces differing content before the
    /// replayer starts following. When `WELCOME` declares `view_seq`, the
    /// replayer starts at that watermark, which must equal `current_seq` and
    /// the view's own watermark.
    ///
    /// Above sequence zero a JOIN with no view is retried for 1/2/4/8/16
    /// seconds and then refused: the only view the client could build is
    /// empty, and cluster-wins would delete every local-only path. At sequence
    /// zero the empty view is exact and allowed. [`Config::allow_empty_view`]
    /// opts into the loss explicitly; the CLI flag is wired separately.
    ///
    /// `applied` and `epoch_seen` are the ctrl-prefix watermark. The returned
    /// parts are split between the uplink and the downlink task.
    ///
    /// When [`Client::with_join_auth`] supplied cluster credentials, the JOIN
    /// also runs the `JOIN_PROOF` exchange (50 §3.2) between `WELCOME` and the
    /// local phase: this client proves possession of the cluster key and its
    /// signing key, and a member answers `JOIN_ACCEPT` with the keys it knows.
    /// A `JOIN_FAIL`, or no answer while a member is online, aborts the JOIN.
    /// A cluster with no online member has nobody to verify the proof; that
    /// case is logged as the known gap and the JOIN proceeds (see
    /// [`Client::join_with_ring`]).
    pub async fn join(&mut self, applied: Seq, epoch_seen: u64) -> Result<ConnParts, ClientError> {
        self.join_with_ring(applied, epoch_seen, None).await
    }

    /// The watermark the next JOIN reports.
    ///
    /// A restart must tell the server what the local disk already applied:
    /// `applied = LocalManifest.at_seq`, `epoch_seen = LocalManifest.epoch`.
    /// The server grants a self view only when the client is caught up (equal
    /// to `current_seq`, or one `LEAVE` behind), so reporting zero after a
    /// restart would make a single-member cluster refuse the view and exit 2.
    /// A missing or unreadable manifest keeps the first-start watermark
    /// `(UNSEQUENCED, 0)`, which preserves the existing empty-view path.
    fn join_watermark(&self) -> (Seq, u64) {
        let Some(root) = self.root.as_ref() else {
            return (Seq::UNSEQUENCED, 0);
        };
        let cluster = self
            .cluster
            .unwrap_or_else(|| ClusterId::from_bytes([0u8; 16]));
        match LocalManifest::load(root.as_ref(), cluster) {
            Some(manifest) => (manifest.at_seq, manifest.epoch),
            None => (Seq::UNSEQUENCED, 0),
        }
    }

    /// JOIN with the watermark persisted by the last clean unmount.
    ///
    /// This is the production entry point: a restart reports what the disk
    /// already applied instead of the first-start zero.
    async fn join_reported(&mut self, ring: &KeyRing) -> Result<ConnParts, ClientError> {
        let (applied, epoch_seen) = self.join_watermark();
        self.join_with_ring(applied, epoch_seen, Some(ring)).await
    }

    /// [`Client::join`] with the cluster key ring.
    ///
    /// The ring is needed to seal the `JOIN_PROOF` envelope and to open the
    /// member's answer. [`Client::run_with_identity`] supplies it; a caller
    /// that configured [`Client::with_join_auth`] but calls [`Client::join`]
    /// without a ring gets a hard error instead of a silently unauthenticated
    /// session.
    pub(crate) async fn join_with_ring(
        &mut self,
        applied: Seq,
        epoch_seen: u64,
        ring: Option<&KeyRing>,
    ) -> Result<ConnParts, ClientError> {
        self.prepare_relay()?;
        let endpoint = self.transport_endpoint()?;
        // A cluster that is above sequence zero but has not published a view
        // yet is retried inside this single JOIN. Each retry is a fresh
        // connection, so the `HELLO` carries the same `applied`/`epoch_seen`
        // watermark again and the new `WELCOME` is authoritative. The proof
        // is re-run on the new connection because its nonces changed.
        let mut retry = JoinRetryPolicy::new();
        let (report, parts, welcome) = loop {
            let options = DialOptions::random().with_client_id(self.config.client_id.to_bytes());
            let mut conn = Conn::dial(&endpoint, options, self.limits).await?;
            conn = conn.with_timeout(self.handshake_timeout);

            let client_nonce = rand::random::<[u8; 32]>();
            let hello = Hello::new(
                ProtoVersion::CURRENT,
                // `VIEW_SOURCE` asks the server to name the view holder in
                // `WELCOME`; without it the server leaves the view fields
                // empty and a manifest-only JOIN has nothing to pull.
                // `VIEW_SELF` lets a single-member cluster answer with the
                // local manifest instead of an empty view. The server grants
                // it only when both sides advertise the capability, the
                // client reports a caught-up watermark, and the gap holds no
                // `ORDERED`.
                Caps::REQUIRED
                    .union(Caps::VIEW_SOURCE)
                    .union(Caps::VIEW_SELF),
                self.config.client_id,
                client_nonce,
            );
            let welcome = conn.hello(hello, applied, epoch_seen).await?;
            check_welcome_view(&welcome)?;
            if self.join_wants_view(&welcome) {
                match retry.next_delay() {
                    Some(delay) => {
                        tracing::warn!(
                            attempt = retry.retries_used(),
                            current_seq = welcome.current_seq.get(),
                            ?delay,
                            "WELCOME has no view above sequence zero; retrying the JOIN"
                        );
                        drop(conn);
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    None => {
                        return Err(ClientError::Join(format!(
                            "cluster is at seq {} but offered no view after {} retries; \
                             refusing to join with an empty view because cluster-wins would \
                             delete local-only paths",
                            welcome.current_seq.get(),
                            retry.max_retries()
                        )));
                    }
                }
            }

            let proto = conn.negotiated().map_or(ProtoVersion::CURRENT, |n| n.proto);
            let mut parts = conn.into_parts()?;
            self.join_proof(&mut parts, &welcome, client_nonce, proto, ring)
                .await?;
            // W17: bring the local tree to the cluster view before the
            // replayer starts following. A remount is cluster-wins:
            // local-only paths are deleted, differing content is replaced,
            // and nothing is merged (39 §2.6, 43 §6.3).
            match self.cluster_wins_joining(&welcome, parts).await {
                Ok((report, parts)) => break (report, parts, welcome),
                Err(error) if is_transient_join(&error) => {
                    // The holder's source slots are full, or it made no
                    // progress inside the relay window. Both are transient
                    // relay conditions, not a broken JOIN: wait and run the
                    // whole exchange again.
                    self.clear_join_relay();
                    match retry.next_delay() {
                        Some(delay) => {
                            tracing::warn!(
                                attempt = retry.retries_used(),
                                ?delay,
                                "view holder relay is unavailable; retrying the JOIN"
                            );
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                        None => return Err(error),
                    }
                }
                Err(error) => return Err(error),
            }
        };
        // The replayer starts where the server's downlink starts. A declared
        // `WELCOME.view_seq` equals `current_seq` (checked above), so this is
        // the same value on the holder path. An injected `JoinView` may carry
        // a manifest older than the cluster (the test harness seeds files at
        // seq zero and then writes during the pull); starting at the
        // manifest's `at_seq` would leave a gap the server will never resend.
        // A snapshot install names its own covered seq.
        let covered = report.covered_seq.unwrap_or(welcome.current_seq);
        let mut replayer = Replayer::new(
            self.config.client_id,
            covered,
            welcome.epoch,
            &self.config.tuning,
            Arc::clone(&self.pending),
        )
        .with_sync(self.sync.clone())
        .with_backpressure(Arc::clone(&self.backpressure));
        // The namespace must describe the same view the disk was brought to.
        // Without this rebuild the first WRITE of an existing path resolves
        // through an empty `S` and fails with ENOENT.
        replayer
            .rebuild_from_manifest(&report.manifest)
            .map_err(|error| ClientError::Join(format!("replayer rebuild: {error:?}")))?;
        self.last_join = Some(report);
        self.replayer = Some(replayer);
        Ok(parts)
    }

    /// Drop the relay state of a JOIN attempt that failed before STEADY.
    ///
    /// The next attempt binds a fresh view session; keeping the old link or
    /// holder would leave a closed session attached to the client.
    fn clear_join_relay(&mut self) {
        self.relay = None;
        self.holder = None;
        self.sync_ports = None;
    }

    /// Cluster-wins with a live downlink when the CLI supplied relay material.
    ///
    /// A manifest-only JOIN is request/answer over the relay session: the
    /// holder's `RELAY` and `STREAM_DATA{BLOCK}` frames must be routed to the
    /// link while `cluster_wins` waits. Without a reader those answers stay in
    /// the events stream and every request times out.
    ///
    /// The JOINING writer owns the uplink for exactly this window:
    /// [`ScopedUplink::start`] takes it, the link writes through its handle,
    /// and [`ScopedUplink::handoff`] returns the one writer for the steady
    /// state. Frames that do not belong to the relay session are kept in
    /// arrival order for the steady-state [`Downlink`].
    async fn cluster_wins_joining(
        &mut self,
        welcome: &Welcome,
        parts: ConnParts,
    ) -> Result<(JoinReport, ConnParts), ClientError> {
        let ConnParts {
            events,
            decoder,
            welcome: parts_welcome,
            uplink,
        } = parts;
        let Some(assembly) = self.sync_assembly.as_ref() else {
            let report = self.cluster_wins(welcome).await?;
            let parts = ConnParts {
                events,
                decoder,
                welcome: parts_welcome,
                uplink,
            };
            return Ok((report, parts));
        };

        // The JOINING writer sends only the relay frames it is given; the
        // connection itself is the keepalive.
        let (scoped, handle) = ScopedUplink::start(uplink);
        let sink: Arc<dyn FrameSink> = Arc::new(handle);
        let (relay, ports) = assembly.ports(welcome, Arc::clone(&sink));
        let relay = Arc::new(relay);
        // The holder answers other clients from the same tree and the same
        // writer. Its default watermark is the view it can describe, not a
        // sequence the local disk does not contain yet.
        let holder = Arc::new(
            Holder::new(
                Arc::clone(assembly.root()),
                Arc::clone(assembly.store()),
                Arc::clone(assembly.ring()),
                assembly.cluster(),
                welcome.view_seq.unwrap_or(welcome.current_seq),
                sink,
            )
            .with_own_session(relay.link().session()),
        );
        self.sync_ports = Some(ports);
        self.relay = Some(Arc::clone(&relay));
        self.holder = Some(holder);

        let mut events = events;
        let mut decoder = decoder;
        // A peer can receive another client's `JOIN_PROOF` while this client
        // is still in `cluster_wins` (the server treats a paired session as a
        // peer before the steady pump exists). Answer it here with the same
        // credentials the pump uses, or the joiner waits until it is kicked.
        let proof = self.join_auth.as_ref().map(|auth| {
            Arc::new(JoinProofResponder::new(
                Arc::clone(auth.master()),
                Arc::clone(auth.signing()),
                Arc::clone(assembly.ring()),
                Arc::clone(&self.keys),
                self.cluster
                    .unwrap_or_else(|| ClusterId::from_bytes([0u8; 16])),
            ))
        });
        let mut reader = JoinReader::new(&mut events, &mut decoder, relay.link(), proof);
        // `JOIN_PROOF` may already have buffered a relay frame; route it
        // before the first request, or the answer would sit behind it.
        for frame in self.take_join_backlog() {
            if let Err(error) = reader.route(frame).await {
                let _ = relay.link().close(crate::sync::SyncEndReason::Cancel).await;
                return Err(error);
            }
        }
        let mut wins = Box::pin(self.cluster_wins(welcome));
        let outcome = loop {
            tokio::select! {
                biased;
                result = &mut wins => break result,
                frame = reader.next() => match frame {
                    Ok(Some(frame)) => {
                        if let Err(error) = reader.route(frame).await {
                            break Err(error);
                        }
                    }
                    Ok(None) => {
                        break Err(ClientError::Join(
                            "downlink ended before cluster-wins completed".to_owned(),
                        ));
                    }
                    Err(error) => break Err(error),
                },
            }
        };
        drop(wins);
        let backlog = reader.into_backlog();
        // Close the view relay session before the writer changes hands. A
        // session left open counts against the holder's source-session limit
        // and makes the next joiner's WELCOME token fail with NoPeer.
        let reason = if outcome.is_ok() {
            crate::sync::SyncEndReason::Done
        } else {
            crate::sync::SyncEndReason::Cancel
        };
        let closed = relay.link().close(reason).await;
        let report = match outcome {
            Ok(report) => {
                closed.map_err(|error| ClientError::Join(format!("relay view close: {error}")))?;
                report
            }
            Err(error) => {
                if let Err(close_error) = closed {
                    tracing::warn!(%close_error, "relay view cancel failed");
                }
                return Err(error);
            }
        };
        let uplink = scoped
            .handoff()
            .await
            .map_err(|error| ClientError::Join(format!("JOINING uplink handoff: {error}")))?;
        self.join_backlog = backlog;
        Ok((
            report,
            ConnParts {
                events,
                decoder,
                welcome: parts_welcome,
                uplink,
            },
        ))
    }

    /// True when the JOIN must wait for a view instead of accepting an empty
    /// one.
    ///
    /// The condition is narrow on purpose. A declared `WELCOME.view_seq`, a
    /// snapshot reference with sync ports, or an injected [`JoinView`] all
    /// give the client a real view. Anything else at `current_seq > 0` is a
    /// hole, and the only empty view the client could build would delete
    /// local-only paths.
    fn join_wants_view(&self, welcome: &Welcome) -> bool {
        !self.config.allow_empty_view
            && !welcome.view_self
            && welcome.current_seq.is_sequenced()
            && welcome.view_seq.is_none()
            && welcome.snapshot_ref.is_none()
            && self.join_view.is_none()
    }

    /// Run the `JOIN_PROOF` exchange after `WELCOME`.
    ///
    /// The proof is sealed with the join key derived from the master key and
    /// the two handshake nonces, so a peer that can open it has proven both
    /// cluster-key possession and authorship. Nothing is trusted before the
    /// answer arrives.
    async fn join_proof(
        &mut self,
        parts: &mut ConnParts,
        welcome: &Welcome,
        client_nonce: [u8; 32],
        proto: ProtoVersion,
        ring: Option<&KeyRing>,
    ) -> Result<(), ClientError> {
        let Some(auth) = self.join_auth.as_ref().map(Arc::clone) else {
            return Ok(());
        };
        let Some(ring) = ring else {
            return Err(ClientError::Join(
                "the JOIN proof needs the cluster key ring".to_owned(),
            ));
        };
        let cluster = self
            .cluster
            .unwrap_or_else(|| ClusterId::from_bytes([0u8; 16]));

        // This client's own entry is the first key it can trust: the server
        // echoes its own ORDERED frames back, and those must verify.
        let own = KeyAnnounce::sign(
            auth.signing().as_ref(),
            &cluster,
            auth.signing().key_epoch(),
            None,
        );
        self.trust_announce(&own)?;

        let proof = Proof::new(
            auth.signing().as_ref(),
            client_nonce,
            welcome.server_nonce,
            welcome.epoch,
            proto,
        );
        let sealed = proof
            .seal(&auth.master, &cluster)
            .map_err(|error| ClientError::Join(format!("join proof: {error}")))?;
        let body = encode_join_proof(&sealed, &client_nonce, &welcome.server_nonce, &own)?;
        let session = SessionId::new(rand::random::<u128>());
        let frame = seal_relay(ring, &auth.nonces(), session, &body)?;
        parts
            .uplink
            .send(&frame)
            .await
            .map_err(|error| ClientError::Join(format!("join proof send: {error}")))?;

        let verdict = self.await_join_verdict(parts, ring, &auth).await?;
        // Close the relay session the proof opened. Left open, the next
        // session this client opens counts as a source change, and the server
        // then puts the peer into its relay cooldown — which would break the
        // first write's data relay.
        if !matches!(verdict, JoinVerdict::NoVerifier) {
            let close = sync_end_frame(session)?;
            parts
                .uplink
                .send(&close)
                .await
                .map_err(|error| ClientError::Join(format!("join relay close: {error}")))?;
        }

        match verdict {
            JoinVerdict::Accepted(entries) => {
                for announce in entries {
                    self.trust_announce(&announce)?;
                }
                Ok(())
            }
            JoinVerdict::Rejected(result) => Err(ClientError::Join(format!(
                "a cluster member rejected the JOIN proof (result {result})"
            ))),
            JoinVerdict::NoAnswer => Err(ClientError::Join(format!(
                "a member is online but did not accept the JOIN proof within {:?}",
                self.join_proof_timeout
            ))),
            JoinVerdict::NoVerifier => {
                // The server answered `TRN_NO_PEER`: no member is online, so
                // nobody can verify this proof. In an empty cluster that is
                // expected — the first client has no peer to prove itself to.
                // The case is recorded rather than faked: the client is
                // trusted because no verifier exists, not because the proof
                // passed.
                tracing::warn!(
                    event = "known_gap",
                    current_seq = welcome.current_seq.get(),
                    members_online = welcome.current_seq.is_sequenced(),
                    "no member answered JOIN_PROOF; the first client is trusted without \
                     verification (F16 known gap)"
                );
                Ok(())
            }
        }
    }

    /// Install one announced key in the directory.
    fn trust_announce(&self, announce: &KeyAnnounce) -> Result<(), ClientError> {
        let mut keys = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
        keys.trust(announce)
            .map(|_| ())
            .map_err(|error| ClientError::Join(format!("key directory: {error}")))
    }

    /// Wait for `JOIN_ACCEPT`/`JOIN_FAIL`, bounded by
    /// [`Client::with_join_proof_timeout`].
    ///
    /// The wait also answers other clients' proofs: two clients that join at
    /// the same time have no settled member to verify them, so each is the
    /// other's verifier. Frames that are not a proof or a verdict are kept for
    /// the downlink, so the handshake cannot swallow an `ORDERED` broadcast.
    async fn await_join_verdict(
        &mut self,
        parts: &mut ConnParts,
        ring: &KeyRing,
        auth: &JoinAuth,
    ) -> Result<JoinVerdict, ClientError> {
        let deadline = tokio::time::Instant::now() + self.join_proof_timeout;
        let opener = Opener::new(ring);
        loop {
            let frame = match parts.decoder.next_frame_owned().map_err(conn_error)? {
                Some(frame) => frame,
                None => {
                    let now = tokio::time::Instant::now();
                    let Some(remaining) = deadline.checked_duration_since(now) else {
                        return Ok(JoinVerdict::NoAnswer);
                    };
                    match tokio::time::timeout(remaining, parts.events.recv()).await {
                        Err(_) => return Ok(JoinVerdict::NoAnswer),
                        Ok(Ok(Some(chunk))) => {
                            parts.decoder.push(&chunk).map_err(conn_error)?;
                            continue;
                        }
                        Ok(Ok(None)) => return Err(ClientError::Connection(ConnError::Closed)),
                        Ok(Err(error)) => {
                            return Err(ClientError::Connection(ConnError::Transport(error)));
                        }
                    }
                }
            };

            match frame.header.msg_type {
                MsgType::RELAY => {
                    let verdict = match opener.open(&frame.header, &frame.prefix, &frame.body) {
                        Ok(plaintext) => {
                            match decode_sealed(MsgType::RELAY, plaintext.as_slice(), &self.limits)
                            {
                                Ok(crate::protocol::Message::Relay(relay)) => {
                                    join_verdict_from_relay(relay)
                                }
                                _ => None,
                            }
                        }
                        Err(_) => None,
                    };
                    match verdict {
                        Some(verdict) => return Ok(verdict),
                        None => {
                            let cluster = self
                                .cluster
                                .unwrap_or_else(|| ClusterId::from_bytes([0u8; 16]));
                            match answer_join_proof(&frame, auth, ring, &self.keys, &cluster) {
                                Some(reply) => {
                                    parts.uplink.send(&reply).await.map_err(|error| {
                                        ClientError::Join(format!(
                                            "join proof answer send: {error}"
                                        ))
                                    })?
                                }
                                None => self.join_backlog.push(frame),
                            }
                        }
                    }
                }
                MsgType::ERROR => {
                    let crate::protocol::Message::Error(error) =
                        decode_plain(MsgType::ERROR, &frame.body, &self.limits)
                            .map_err(|error| ClientError::Connection(ConnError::Message(error)))?
                    else {
                        self.join_backlog.push(frame);
                        continue;
                    };
                    // No peer means no member is online: nobody can verify.
                    // Every other error is a real handshake failure.
                    if error.reason == TrnReason::NoPeer {
                        return Ok(JoinVerdict::NoVerifier);
                    }
                    return Err(ClientError::Connection(ConnError::Server {
                        reason: error.reason,
                        detail: error.detail.to_vec(),
                    }));
                }
                MsgType::KICK => {
                    let crate::protocol::Message::Kick(kick) =
                        decode_plain(MsgType::KICK, &frame.body, &self.limits)
                            .map_err(|error| ClientError::Connection(ConnError::Message(error)))?
                    else {
                        self.join_backlog.push(frame);
                        continue;
                    };
                    return Err(ClientError::Connection(ConnError::Kicked(kick.reason)));
                }
                _ => self.join_backlog.push(frame),
            }
        }
    }

    /// Bring the local tree to the cluster view.
    ///
    /// A positive watermark with no view is refused unless
    /// [`Config::allow_empty_view`] was set: cluster-wins over an empty view
    /// deletes every local-only path, and the server keeps no replay window
    /// to rebuild the missing history. At watermark zero the empty view is
    /// exact and always allowed.
    async fn cluster_wins(&self, welcome: &Welcome) -> Result<JoinReport, ClientError> {
        let root = match &self.root {
            Some(root) => Arc::clone(root),
            None => Arc::new(RootFd::open_before_mount(&self.config.mountpoint)?),
        };
        let cluster = self
            .cluster
            .unwrap_or_else(|| ClusterId::from_bytes([0u8; 16]));
        let ResolvedView {
            view,
            chunks,
            delta,
            view_seq,
            covered_seq,
        } = self.remote_view(welcome).await?;
        // Check before the diff: a rejected view must not delete anything.
        let view_seq = view_watermark(welcome.view_seq, view_seq)?;
        let epoch = welcome.epoch;
        let cache_cluster = self.cluster;
        let manifest = view.manifest;
        let view_blockmap = view.blockmap;
        let at_seq = manifest.at_seq;
        // Keep the exact view the replayer will rebuild from. It is cloned
        // before the apply task takes ownership.
        let report_manifest = manifest.clone();

        // The plan is a directory walk plus comparison: blocking work.
        let plan_root = Arc::clone(&root);
        let plan_manifest = manifest.clone();
        let plan = tokio::task::spawn_blocking(move || {
            let tree = DiskTree::new(plan_root.as_ref(), cache_cluster);
            let local = tree.cached_manifest();
            crate::sync::manifest::diff::plan(local.as_ref(), &plan_manifest, &tree, cluster)
        })
        .await
        .map_err(|_| ClientError::Task("join plan task failed".to_owned()))??;

        if welcome.view_self {
            // A self view must describe the disk exactly. Anything else is a
            // stale manifest or a local edit; refuse before deleting or
            // pulling a single byte.
            let counts = plan.counts();
            if counts.transfers() != 0 || counts.local_only != 0 {
                return Err(ClientError::Join(format!(
                    "self view disagrees with the local tree: {} transfers, {} local-only paths; \
                     refusing to delete or pull",
                    counts.transfers(),
                    counts.local_only
                )));
            }
        }

        // Pull only the blockmap parts the plan needs. A `JoinView` may
        // already carry a complete map; a snapshot view does not.
        let blockmap = if needs_blockmap_pull(&plan, &manifest, &view_blockmap) {
            let ports = self.sync_ports.as_ref().ok_or_else(|| {
                ClientError::Join("the plan needs a blockmap but no ports were supplied".to_owned())
            })?;
            let service = ManifestService::new(ports);
            let index_ref = ports.link.request_blockmap_index(manifest.at_seq).await?;
            let index = service.fetch_blockmap_index(&index_ref).await?;
            if !blockmap_index_matches(&index, &manifest) {
                return Err(ClientError::Join(format!(
                    "blockmap index covers seq {} for {} files, manifest is seq {} with {} files",
                    index.at_seq.get(),
                    index.file_count(),
                    manifest.at_seq.get(),
                    manifest.len()
                )));
            }
            let parts = plan.blockmap_parts(&index, &manifest);
            service.fetch_blockmap(&index, &parts).await?
        } else {
            view_blockmap
        };

        // The holder's bytes are not in the local cache yet. Pull every block
        // the plan needs before `ClusterWins` reads that cache; `TypeReplace`
        // and remote-only files otherwise fail with `ChunkUnavailable`.
        if let Some(relay) = &self.relay {
            let fetched = fetch_blocks(&plan, &manifest, &blockmap, relay.chunks().as_ref()).await;
            fetched.into_result().map_err(ClientError::Sync)?;
        }

        let task_root = Arc::clone(&root);
        let result = tokio::task::spawn_blocking(move || -> Result<JoinReport, SyncError> {
            let engine = OxideEngine::default();
            let outcome = ClusterWins {
                root: &task_root,
                remote: &manifest,
                blockmap: &blockmap,
                chunks: chunks.as_ref(),
                delta: delta.as_deref(),
                engine: &engine,
            }
            .apply(&plan)?;
            if let Some(cluster_id) = cache_cluster {
                LocalManifest {
                    cluster_id,
                    at_seq: manifest.at_seq,
                    epoch,
                    manifest: manifest.clone(),
                }
                .store(&task_root)?;
            }
            Ok(JoinReport {
                at_seq,
                view_seq,
                manifest: report_manifest,
                counts: plan.counts(),
                removed: outcome.report.removed,
                replaced: outcome.report.replaced,
                installed: outcome.report.installed,
                dirs: outcome.report.dirs,
                attrs: outcome.report.attrs,
                symlinks: outcome.symlinks,
                covered_seq,
            })
        })
        .await
        .map_err(|_| ClientError::Task("cluster-wins task failed".to_owned()))?;
        result.map_err(ClientError::Sync)
    }

    /// Resolve the remote view: an injected view, a pulled snapshot, or the
    /// empty cluster.
    ///
    /// A `WELCOME` that names a view the client cannot reach is an error, not
    /// an excuse to build an empty view. The same holds above sequence zero
    /// with no view at all unless [`Config::allow_empty_view`] is set.
    async fn remote_view(&self, welcome: &Welcome) -> Result<ResolvedView, ClientError> {
        if let Some(view) = &self.join_view {
            let remote = view.remote();
            return Ok(ResolvedView {
                view_seq: remote.manifest.at_seq,
                view: remote,
                chunks: view.chunks(),
                delta: view.delta(),
                covered_seq: None,
            });
        }
        if welcome.view_self {
            // Single-member cluster: the server tells this client that its own
            // local manifest is the view. Refuse on any disagreement instead
            // of falling back to an empty view, which would delete files.
            let root = self.root.as_ref().ok_or_else(|| {
                ClientError::Join(
                    "WELCOME declares a self view but the root is not mounted".to_owned(),
                )
            })?;
            let cluster = self
                .cluster
                .unwrap_or_else(|| ClusterId::from_bytes([0u8; 16]));
            let local = LocalManifest::load(root, cluster).ok_or_else(|| {
                ClientError::Join(
                    "WELCOME declares a self view but no valid local manifest exists".to_owned(),
                )
            })?;
            if local.epoch != welcome.epoch {
                return Err(ClientError::Join(format!(
                    "self view epoch {} does not match WELCOME epoch {}",
                    local.epoch, welcome.epoch
                )));
            }
            // A clean unmount persists `at_seq = applied`. A crash between
            // the server sequencing a `LEAVE` and the local apply leaves the
            // manifest exactly one behind; that frame changes no file. Accept
            // only that single-step gap, and only when the diff below still
            // shows no transfer and no local-only path.
            let at_seq = local.at_seq;
            if at_seq != welcome.current_seq && at_seq.checked_next() != Some(welcome.current_seq) {
                return Err(ClientError::Join(format!(
                    "self view covers seq {} but WELCOME current seq is {}",
                    at_seq.get(),
                    welcome.current_seq.get()
                )));
            }
            let manifest = local.manifest;
            let blockmap = Blockmap::new(at_seq, vec![0u32; manifest.len()], Vec::new())?;
            return Ok(ResolvedView {
                view: RemoteView {
                    reference: None,
                    manifest,
                    blockmap,
                },
                chunks: Arc::new(EmptyChunks),
                delta: None,
                // The replayer starts at the server watermark. The one
                // accepted gap is a `LEAVE`, which the disk does not need to
                // apply; starting at `current_seq` skips it without a hole.
                view_seq: welcome.current_seq,
                covered_seq: None,
            });
        }
        if welcome.view_seq.is_some() {
            // Manifest-only JOIN: the holder serves its current manifest.
            // This path comes before the snapshot and the empty view because
            // a holder-backed cluster at watermark zero still has files; the
            // empty view is exact only when no holder exists.
            if let Some(ports) = &self.sync_ports {
                // Ask for exactly the sequence the server declared. `None`
                // would let the holder answer with its own current seq, which
                // may be ahead of the view this JOIN is about to install.
                let manifest_ref = ports.link.request_manifest(welcome.view_seq).await?;
                let manifest = ManifestService::new(ports).fetch(&manifest_ref).await?;
                let view_seq = manifest.at_seq;
                let blockmap =
                    Blockmap::new(manifest.at_seq, vec![0u32; manifest.len()], Vec::new())?;
                let cache = ports.cache.clone().ok_or_else(|| {
                    ClientError::Join("sync ports have no chunk cache".to_owned())
                })?;
                return Ok(ResolvedView {
                    view: RemoteView {
                        reference: None,
                        manifest,
                        blockmap,
                    },
                    chunks: cache,
                    delta: ports.delta.clone(),
                    view_seq,
                    covered_seq: None,
                });
            }
            // Without relay ports the holder's manifest is unreachable. At
            // watermark zero the empty view is exact, so the existing zero
            // branch below is the safe fallback; above zero it must refuse.
            if welcome.current_seq != Seq::UNSEQUENCED {
                return Err(ClientError::Join(
                    "WELCOME names a view holder but no sync ports were supplied".to_owned(),
                ));
            }
        }
        if let Some(ports) = &self.sync_ports {
            if let Some(reference) = welcome.snapshot_ref {
                let config = SyncConfig::new();
                let installer = crate::sync::snapshot::Installer::new(ports, &config);
                let pulled = installer.pull(&reference).await?;
                let installed = installer.install(pulled)?;
                let manifest_ref = ports.link.request_manifest(None).await?;
                let manifest = ManifestService::new(ports).fetch(&manifest_ref).await?;
                let view_seq = manifest.at_seq;
                let blockmap =
                    Blockmap::new(manifest.at_seq, vec![0u32; manifest.len()], Vec::new())?;
                let cache = ports.cache.clone().ok_or_else(|| {
                    ClientError::Join("sync ports have no chunk cache".to_owned())
                })?;
                return Ok(ResolvedView {
                    view: RemoteView {
                        reference: Some(reference),
                        manifest,
                        blockmap,
                    },
                    chunks: cache,
                    delta: ports.delta.clone(),
                    view_seq,
                    covered_seq: Some(installed.covered_seq),
                });
            }
        }
        if welcome.current_seq == Seq::UNSEQUENCED {
            // At watermark zero the empty view is exact, whether or not the
            // server names a holder: there is no history to miss.
            return Ok(ResolvedView {
                view: RemoteView {
                    reference: None,
                    manifest: Manifest::new(Seq::UNSEQUENCED, Vec::new()),
                    blockmap: Blockmap::new(Seq::UNSEQUENCED, Vec::new(), Vec::new())?,
                },
                chunks: Arc::new(EmptyChunks),
                delta: None,
                view_seq: Seq::UNSEQUENCED,
                covered_seq: None,
            });
        }
        if welcome.snapshot_ref.is_some() {
            return Err(ClientError::Join(
                "WELCOME names a snapshot but no sync ports were supplied".to_owned(),
            ));
        }
        if !self.config.allow_empty_view {
            return Err(ClientError::Join(format!(
                "cluster is at seq {} but offers no view; refusing to join with an \
                 empty view because cluster-wins would delete local-only paths \
                 (set allow_empty_view to accept the loss)",
                welcome.current_seq.get()
            )));
        }
        // Explicit opt-in: the loss is recorded instead of silent.
        tracing::warn!(
            current_seq = welcome.current_seq.get(),
            "joining with an empty view by explicit opt-in; \
             local-only paths will be deleted and history is not replayed"
        );
        Ok(ResolvedView {
            view: RemoteView {
                reference: None,
                manifest: Manifest::new(welcome.current_seq, Vec::new()),
                blockmap: Blockmap::new(welcome.current_seq, Vec::new(), Vec::new())?,
            },
            chunks: Arc::new(EmptyChunks),
            delta: None,
            view_seq: welcome.current_seq,
            covered_seq: None,
        })
    }

    /// Start the lifecycle and run until it exits.
    ///
    /// The driver translates [`Action`]s into effects and feeds the results
    /// back as events. The FUSE adapter is W13a's local backing; W13b attaches
    /// the write path to [`Outbox`]; [`Client::join`] runs the W17
    /// cluster-wins step before the replayer follows the broadcast.
    pub async fn run(self, ring: Arc<KeyRing>) -> Result<i32, ClientError> {
        let identity: Arc<dyn Identity + Send + Sync> =
            Arc::new(LocalIdentity::new(self.config.client_id));
        self.run_with_identity(ring, identity).await
    }

    /// Run with an explicit signing identity.
    ///
    /// The production path supplies the persisted W7 [`crate::crypto::SigningKey`];
    /// [`Client::run`] uses a per-process in-memory key for tests and for the
    /// volatile local-only mode.
    pub async fn run_with_identity(
        self,
        ring: Arc<KeyRing>,
        identity: Arc<dyn Identity + Send + Sync>,
    ) -> Result<i32, ClientError> {
        if identity.client_id() != self.config.client_id {
            return Err(ClientError::Join(
                "signing identity does not match config.client_id".to_owned(),
            ));
        }
        let mut client = self;
        client.relay_ring = Some(Arc::clone(&ring));
        let mut events = VecDeque::from([Event::Prepared(Ok(()))]);
        let mut lock: Option<OwnedFd> = None;
        let mut status_writer: Option<StatusWriter> = None;
        let status_state = Arc::new(StatusState::default());
        let mut backing: Option<Arc<PosixBacking>> = None;
        let mut nodes: Option<Arc<NodeTable>> = None;
        let mut notify: Option<NotifyHandle> = None;
        let mut mount: Option<MountHandle> = None;
        let mut uplink: Option<Uplink> = None;
        let mut uplink_task: Option<tokio::task::JoinHandle<()>> = None;
        let data_cache = Arc::new(DataCache::new());
        // Answers to a peer's JOIN_PROOF: the replay pump decides, the uplink
        // task writes, so the single-writer rule holds.
        let (control_tx, control_rx) = mpsc::channel::<FrameBuf>(16);
        let mut control_rx = Some(control_rx);
        let (task_tx, mut task_rx) = mpsc::channel::<Event>(16);

        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        let status_period = client
            .config
            .tuning
            .status_interval
            .max(Duration::from_millis(100));
        let mut status_tick = tokio::time::interval(status_period);
        status_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            while let Some(event) = events.pop_front() {
                let actions = client.on(event);
                write_status(&status_writer, &client, &status_state);
                for action in actions {
                    match action {
                        Action::AcquireLock => match acquire_lock(&client.config, &mut lock) {
                            Ok(dir) => {
                                let period = client
                                    .config
                                    .tuning
                                    .status_interval
                                    .max(Duration::from_millis(100));
                                status_writer = Some(StatusWriter::new(dir, period));
                                events.push_back(Event::LockAcquired(Ok(())));
                            }
                            Err(error) => events.push_back(Event::LockAcquired(Err(error))),
                        },
                        Action::CleanupStale => {
                            events.push_back(Event::Cleaned(cleanup_stale(
                                &client.config.mountpoint,
                            )));
                        }
                        Action::AuditJournal => {
                            // W14 owns the manifest/journal record. The action
                            // stays in the machine so the transition order is
                            // fixed before that code lands.
                        }
                        Action::MountFuse => {
                            let gate = client.gate_handle();
                            let outbox = Arc::clone(client.outbox());
                            let pending = Arc::clone(client.pending());
                            let sync = client.sync.clone();
                            let result = mount_fuse(
                                &client.config,
                                client.allow_other,
                                gate,
                                outbox,
                                pending,
                                sync,
                                &mut backing,
                                &mut client.root,
                                &mut nodes,
                                &mut notify,
                            );
                            match result {
                                Ok(session) => {
                                    mount = Some(session);
                                    events.push_back(Event::FuseMounted(Ok(())));
                                }
                                Err(error) => {
                                    tracing::error!(%error, "FUSE mount failed");
                                    events.push_back(Event::FuseMounted(Err(MountError::Fuse)));
                                }
                            }
                        }
                        Action::StartJoin => match client.join_reported(&ring).await {
                            Ok(parts) => {
                                // The JOINING scoped writer handed the uplink
                                // back; route the relay link to the steady
                                // control queue before the uplink task starts.
                                let relay = client.take_relay();
                                // Keep the holder on the client so the
                                // unmount path can persist the final manifest;
                                // the pump gets its own handle.
                                let holder = client.holder.clone();
                                let sink: Arc<dyn FrameSink> = Arc::new(control_tx.clone());
                                if let Some(assembly) = &relay {
                                    assembly.rebind(Arc::clone(&sink));
                                }
                                if let Some(holder) = &holder {
                                    // The holder starts at the WELCOME view and
                                    // follows the replay watermark once STEADY
                                    // publishes it.
                                    holder.track_applied_seq(Arc::clone(&status_state.applied));
                                    holder.rebind(sink);
                                }
                                let ConnParts {
                                    events: downlink_events,
                                    decoder,
                                    welcome,
                                    uplink: uplink_part,
                                } = parts;
                                uplink = Some(uplink_part);
                                let (downlink, downlink_rx, _handle) = Downlink::with_decoder(
                                    downlink_events,
                                    decoder,
                                    client.downlink_depth,
                                );
                                let join_backlog = client.take_join_backlog();
                                let backlog_len = join_backlog.len();
                                let downlink = downlink.with_backlog(join_backlog);
                                let downlink = downlink.with_observers(
                                    Arc::clone(client.counters()),
                                    Arc::clone(client.conntrace()),
                                );
                                let outcome_tx = task_tx.clone();
                                tokio::spawn(async move {
                                    let outcome = downlink.run().await;
                                    let event = match outcome {
                                        Ok(DownlinkOutcome::Eof) => {
                                            tracing::info!("downlink ended at end of stream");
                                            Event::Disconnected(Cause::Eof)
                                        }
                                        Ok(DownlinkOutcome::Kicked(reason)) => {
                                            tracing::warn!(?reason, "downlink ended: kicked");
                                            Event::Kick(reason)
                                        }
                                        Ok(DownlinkOutcome::ServerError { reason }) => {
                                            tracing::error!(
                                                ?reason,
                                                "downlink ended: terminal server error"
                                            );
                                            Event::Disconnected(Cause::Server)
                                        }
                                        Ok(DownlinkOutcome::ReceiverGone) => {
                                            tracing::warn!("downlink ended: replay receiver gone");
                                            Event::Disconnected(Cause::Internal)
                                        }
                                        Err(error) => {
                                            tracing::error!(%error, "downlink ended: {error}");
                                            Event::Disconnected(Cause::Transport)
                                        }
                                    };
                                    let _ = outcome_tx.send(event).await;
                                });
                                if let Some(replayer) = client.replayer.as_ref() {
                                    status_state
                                        .epoch
                                        .store(replayer.epoch(), Ordering::Relaxed);
                                    status_state
                                        .applied
                                        .store(replayer.applied().get(), Ordering::Relaxed);
                                }
                                if let Some(replayer) = client.replayer.take() {
                                    let store = Arc::clone(backing.as_ref().ok_or_else(|| {
                                        ClientError::Task("missing backing".to_string())
                                    })?);
                                    #[cfg(feature = "fuse")]
                                    let replay_backing: Arc<
                                        dyn ReplayBacking,
                                    > = match (&notify, &nodes) {
                                        (Some(notify), Some(nodes)) => {
                                            Arc::new(crate::fuse::ReplayView::new(
                                                Arc::clone(&store),
                                                Arc::clone(nodes),
                                                notify.clone(),
                                            ))
                                        }
                                        _ => Arc::clone(&store) as Arc<dyn ReplayBacking>,
                                    };
                                    #[cfg(not(feature = "fuse"))]
                                    let replay_backing: Arc<
                                        dyn ReplayBacking,
                                    > = store;
                                    spawn_replay_pump(
                                        replayer,
                                        downlink_rx,
                                        replay_backing,
                                        welcome.epoch,
                                        Arc::clone(&ring),
                                        Arc::clone(&data_cache),
                                        Arc::clone(client.counters()),
                                        Arc::clone(&status_state),
                                        task_tx.clone(),
                                        client.join_auth.as_ref().map(|auth| VerifyContext {
                                            auth: Arc::clone(auth),
                                            keys: Arc::clone(&client.keys),
                                            cluster: client.cluster.unwrap_or_else(|| {
                                                ClusterId::from_bytes([0u8; 16])
                                            }),
                                            control: control_tx.clone(),
                                        }),
                                        relay.as_ref().map(|assembly| assembly.link()),
                                        holder,
                                        backlog_len,
                                    );
                                }
                                let view_seq = client
                                    .last_join
                                    .as_ref()
                                    .map_or(welcome.current_seq, |report| report.view_seq);
                                events.push_back(Event::Joined(Ok(JoinOutcome {
                                    epoch: welcome.epoch,
                                    covered: view_seq.get(),
                                })));
                            }
                            Err(error) => {
                                tracing::error!(%error, "JOIN failed");
                                events.push_back(Event::Joined(Err(JoinError::Handshake)));
                            }
                        },
                        Action::OpenWriteGate => {
                            if uplink_task.is_none() {
                                match (uplink.take(), nodes.as_ref(), backing.as_ref()) {
                                    (Some(uplink_part), Some(nodes), Some(store)) => {
                                        let mut task = UplinkTask::new(
                                            Arc::clone(client.outbox()),
                                            uplink_part,
                                            Arc::clone(&identity),
                                            Arc::clone(&ring),
                                            Arc::clone(nodes),
                                            Arc::clone(store),
                                            Arc::clone(client.counters()),
                                            Arc::clone(client.conntrace()),
                                            status_state.watermark(),
                                            task_tx.clone(),
                                        );
                                        match control_rx.take() {
                                            Some(control) => {
                                                task = task.with_control(control);
                                            }
                                            None => tracing::warn!(
                                                "uplink restarted without a join-proof answer channel"
                                            ),
                                        }
                                        uplink_task = Some(tokio::spawn(task.run()));
                                    }
                                    _ => {
                                        tracing::error!("uplink cannot start without mount state");
                                        events.push_back(Event::Fatal(FatalError::Internal));
                                    }
                                }
                            }
                        }
                        Action::CloseWriteGate => {
                            if let Some(task) = uplink_task.take() {
                                task.abort();
                            }
                        }
                        Action::Quiesce(duration) => {
                            tokio::time::sleep(duration).await;
                        }
                        Action::Flush(_) => {
                            if let Some(store) = backing.as_ref() {
                                let store = Arc::clone(store);
                                let result = tokio::task::spawn_blocking(move || {
                                    BackingStore::syncfs(store.as_ref())
                                })
                                .await;
                                if let Ok(Err(error)) = result {
                                    tracing::warn!(%error, "unmount flush failed");
                                }
                            }
                            events.push_back(Event::FlushDone);
                        }
                        Action::Unmount => {
                            // The clean unmount is the last chance to persist
                            // the applied manifest; a crash leaves the JOIN
                            // snapshot in place and self view refuses it.
                            persist_manifest(&client, &status_state).await;
                            if let Some(task) = uplink_task.take() {
                                task.abort();
                            }
                            let result = unmount(&mut mount, &client.config.mountpoint).await;
                            events.push_back(Event::UnmountTried(result));
                        }
                        Action::DegradeReadOnly => {
                            // The gate is already EROFS; the mount stays.
                            tracing::error!("unmount exhausted; serving read-only");
                        }
                        Action::ReleaseLock => {
                            lock.take();
                        }
                        Action::Exit(code) => {
                            if let Some(task) = uplink_task.take() {
                                task.abort();
                            }
                            uplink.take();
                            write_status(&status_writer, &client, &status_state);
                            return Ok(code);
                        }
                    }
                }
            }

            tokio::select! {
                biased;
                _ = status_tick.tick() => write_status(&status_writer, &client, &status_state),
                _ = interrupt.recv() => events.push_back(Event::Signal(Sig::Int)),
                _ = terminate.recv() => events.push_back(Event::Signal(Sig::Term)),
                _ = hangup.recv() => events.push_back(Event::Signal(Sig::Hup)),
                event = task_rx.recv() => {
                    match event {
                        Some(event) => events.push_back(event),
                        None => events.push_back(Event::Disconnected(Cause::Internal)),
                    }
                }
            }
        }
    }
}

/// JOINING downlink router.
///
/// The steady-state [`Downlink`] cannot own the stream yet: `cluster-wins`
/// needs the relay answers first, and the caller still owns
/// `ConnParts.events`. This reader borrows both, routes only frames that
/// belong to the relay session, and keeps every other frame for the
/// steady-state downlink in arrival order.
struct JoinReader<'a> {
    events: &'a mut EventsStream,
    decoder: &'a mut FrameDecoder,
    link: Arc<RelaySyncLink>,
    /// Answers a peer's `JOIN_PROOF` while this client is still JOINING.
    proof: Option<Arc<JoinProofResponder>>,
    backlog: Vec<FrameBuf>,
}

impl<'a> JoinReader<'a> {
    fn new(
        events: &'a mut EventsStream,
        decoder: &'a mut FrameDecoder,
        link: Arc<RelaySyncLink>,
        proof: Option<Arc<JoinProofResponder>>,
    ) -> Self {
        Self {
            events,
            decoder,
            link,
            proof,
            backlog: Vec::new(),
        }
    }

    /// Next complete frame, or `None` when the stream ended.
    async fn next(&mut self) -> Result<Option<FrameBuf>, ClientError> {
        loop {
            if let Some(frame) = self.decoder.next_frame_owned().map_err(conn_error)? {
                return Ok(Some(frame));
            }
            match self.events.recv().await {
                Ok(Some(chunk)) => self.decoder.push(&chunk).map_err(conn_error)?,
                Ok(None) => return Ok(None),
                Err(error) => {
                    return Err(ClientError::Connection(
                        crate::client::net::ConnError::Transport(error),
                    ));
                }
            }
        }
    }

    /// Route one frame; non-relay frames are kept for the steady downlink.
    async fn route(&mut self, frame: FrameBuf) -> Result<(), ClientError> {
        match frame.header.msg_type {
            // A KICK or ERROR ends the session. Waiting for the relay request
            // timeout would delay the same failure by ten seconds.
            MsgType::KICK => {
                let Message::Kick(kick) =
                    decode_plain(MsgType::KICK, &frame.body, &Limits::default())
                        .map_err(|error| ClientError::Connection(ConnError::Message(error)))?
                else {
                    return Err(ClientError::Connection(ConnError::Unexpected(
                        MsgType::KICK,
                    )));
                };
                return Err(ClientError::Connection(ConnError::Kicked(kick.reason)));
            }
            MsgType::ERROR => {
                let Message::Error(error) =
                    decode_plain(MsgType::ERROR, &frame.body, &Limits::default())
                        .map_err(|error| ClientError::Connection(ConnError::Message(error)))?
                else {
                    return Err(ClientError::Connection(ConnError::Unexpected(
                        MsgType::ERROR,
                    )));
                };
                // No peer is a transient sync failure: the holder's relay
                // slot may still be draining. Keep it out of the fatal
                // connection class so a caller can retry the JOIN.
                if error.reason == TrnReason::NoPeer {
                    return Err(ClientError::Sync(SyncError::Link("NoPeer".to_owned())));
                }
                return Err(ClientError::Connection(ConnError::Server {
                    reason: error.reason,
                    detail: error.detail.to_vec(),
                }));
            }
            MsgType::RELAY => {
                if !self.link.deliver(&frame) {
                    // Not a request for this client's view session. It may
                    // be another joiner's proof: the server forwards it to a
                    // peer whose steady pump does not exist yet. Answer it
                    // through the JOINING writer; otherwise keep the frame
                    // for the steady downlink in arrival order.
                    let reply = self.proof.as_ref().and_then(|proof| proof.answer(&frame));
                    match reply {
                        Some(reply) => self
                            .link
                            .send_frame(reply)
                            .await
                            .map_err(|error| ClientError::Sync(error.into()))?,
                        None => self.backlog.push(frame),
                    }
                }
            }
            MsgType::STREAM_DATA => match self.link.deliver_stream(&frame).await {
                Ok(true) => {}
                Ok(false) => self.backlog.push(frame),
                Err(error) => return Err(ClientError::Sync(error.into())),
            },
            _ => self.backlog.push(frame),
        }
        Ok(())
    }

    fn into_backlog(self) -> Vec<FrameBuf> {
        self.backlog
    }
}

/// Whether a JOIN failed for a relay condition that a fresh attempt may cure.
///
/// The server answers `TRN_NO_PEER` when every source slot on the holder is
/// busy. The relay link marks a request that received no byte for the whole
/// progress window with the `transient:` prefix. A JOIN retries both with
/// the normal backoff; every other sync error stays fatal for the attempt.
fn is_transient_join(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::Sync(SyncError::Link(text))
            if text == "NoPeer" || text.starts_with("transient:")
    )
}

fn acquire_lock(
    config: &Config,
    lock: &mut Option<OwnedFd>,
) -> Result<RuntimeDir, lifecycle::LockError> {
    let dir = RuntimeDir::create_in(&config.run_dir, &config.mount_id)
        .map_err(|_| lifecycle::LockError::Io)?;
    let held = dir.acquire_lock().map_err(|err| {
        if err == Errno::EAGAIN {
            lifecycle::LockError::Busy
        } else {
            lifecycle::LockError::Io
        }
    })?;
    *lock = Some(held);
    Ok(dir)
}

/// Persist the manifest the replayer has applied, atomically.
///
/// `holder.view_for` rebuilds the manifest from the current disk (or reuses
/// its cache after checking the disk), so `at_seq` names exactly the state
/// the caller is about to unmount. A missing root, an unsequenced watermark
/// or a failed rebuild only logs: the unmount must still finish.
async fn persist_manifest(client: &Client, status: &StatusState) {
    let (Some(holder), Some(root)) = (client.holder.as_ref(), client.root.as_ref()) else {
        return;
    };
    let at_seq = Seq(status.applied.load(Ordering::Relaxed));
    if !at_seq.is_sequenced() {
        return;
    }
    let cluster = client
        .cluster
        .unwrap_or_else(|| ClusterId::from_bytes([0u8; 16]));
    let epoch = status.epoch.load(Ordering::Relaxed);
    match holder.view_for(at_seq).await {
        Ok(view) => {
            let cache = LocalManifest {
                cluster_id: cluster,
                at_seq,
                epoch,
                manifest: view.manifest().clone(),
            };
            if let Err(error) = cache.store(root.as_ref()) {
                tracing::warn!(%error, "manifest cache write failed");
            }
        }
        Err(error) => tracing::warn!(%error, "manifest cache view build failed"),
    }
}

/// Derive the local content-cache key from the cluster control key.
///
/// The cache is local, but its blobs are sealed. Binding the key to the
/// cluster key means a cache copied from another cluster cannot be opened,
/// and the context string keeps it separate from every protocol key.
fn chunk_cache_key(ring: &KeyRing) -> [u8; 32] {
    blake3::derive_key("sm/v1/chunk-cache", ring.ctrl_key())
}

fn cleanup_stale(mountpoint: &Path) -> Result<(), lifecycle::CleanupError> {
    if !is_mounted(mountpoint) {
        return Ok(());
    }
    let status = std::process::Command::new("fusermount3")
        .arg("-u")
        .arg(mountpoint)
        .status();
    match status {
        Ok(status) if status.success() => Ok(()),
        _ => Err(lifecycle::CleanupError::StaleMount),
    }
}

fn is_mounted(mountpoint: &Path) -> bool {
    let needle = mountpoint.to_string_lossy();
    std::fs::read_to_string("/proc/mounts")
        .map(|text| {
            text.lines().any(|line| {
                line.split_whitespace()
                    .nth(1)
                    .map(|candidate| candidate == needle.as_ref())
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// True when the plan needs blocks that the supplied blockmap cannot name.
fn needs_blockmap_pull(
    plan: &crate::sync::DiffPlan,
    remote: &Manifest,
    blockmap: &Blockmap,
) -> bool {
    plan.transfers().any(|item| {
        item.kind.needs_blockmap()
            && item.remote.is_some_and(|index| {
                remote.entry(index).is_some_and(|entry| {
                    entry.block_count > 0
                        && blockmap.file_blocks(index).is_none_or(|ids| {
                            u32::try_from(ids.len()).unwrap_or(u32::MAX) != entry.block_count
                        })
                })
            })
    })
}

/// True when `index` describes the same sequence and file set as `manifest`.
///
/// A holder may answer a blockmap request from a newer applied sequence than
/// the manifest the JOIN is installing. Applying that map would name blocks
/// for the wrong files, so the JOIN refuses before any diff runs.
fn blockmap_index_matches(
    index: &crate::sync::manifest::BlockmapIndex,
    manifest: &Manifest,
) -> bool {
    index.at_seq == manifest.at_seq
        && usize::try_from(index.file_count()).ok() == Some(manifest.len())
}

#[cfg(feature = "fuse")]
type MountHandle = fuser::BackgroundSession;

#[cfg(feature = "fuse")]
type NotifyHandle = crate::fuse::Notify;

#[cfg(not(feature = "fuse"))]
#[derive(Debug)]
struct MountHandle;

#[cfg(not(feature = "fuse"))]
#[derive(Clone, Debug)]
struct NotifyHandle;

#[cfg(feature = "fuse")]
#[allow(clippy::too_many_arguments)]
fn mount_fuse(
    config: &Config,
    allow_other: bool,
    gate: Arc<WriteGate>,
    outbox: Arc<Outbox>,
    pending: Arc<PendingOverlay>,
    sync: SyncHandle,
    backing: &mut Option<Arc<PosixBacking>>,
    root: &mut Option<Arc<RootFd>>,
    nodes: &mut Option<Arc<NodeTable>>,
    notify: &mut Option<NotifyHandle>,
) -> Result<MountHandle, ClientError> {
    let root_arc = Arc::new(RootFd::open_before_mount(&config.mountpoint)?);
    let table = Arc::new(NodeTable::new());
    let store = Arc::new(PosixBacking::with_nodes(
        Arc::clone(&root_arc),
        Arc::clone(&table),
    ));
    let path =
        crate::fuse::WritePath::new(gate, outbox, pending, config.instance, config.client_id)
            .with_sync(sync);
    let filesystem = crate::fuse::FuseFs::with_write_path(Arc::clone(&store), path);
    let handle = filesystem.notify_handle();
    let session = fuser::Session::new(
        filesystem,
        &config.mountpoint,
        &crate::fuse::mount_config_with(allow_other),
    )?
    .spawn()?;
    // The replayer's materialisation must drop the kernel view; without a
    // session notifier the short TTLs would be the only bound.
    handle.attach(session.notifier());
    *backing = Some(store);
    *root = Some(root_arc);
    *nodes = Some(table);
    *notify = Some(handle);
    Ok(session)
}

#[cfg(not(feature = "fuse"))]
#[allow(clippy::too_many_arguments)]
fn mount_fuse(
    _config: &Config,
    _allow_other: bool,
    _gate: Arc<WriteGate>,
    _outbox: Arc<Outbox>,
    _pending: Arc<PendingOverlay>,
    _sync: SyncHandle,
    _backing: &mut Option<Arc<PosixBacking>>,
    _root: &mut Option<Arc<RootFd>>,
    _nodes: &mut Option<Arc<NodeTable>>,
    _notify: &mut Option<NotifyHandle>,
) -> Result<MountHandle, ClientError> {
    Err(ClientError::FuseDisabled)
}

/// How long one external unmount command may run before it is killed.
#[cfg(feature = "fuse")]
const EXTERNAL_UNMOUNT_TIMEOUT: Duration = Duration::from_secs(2);

/// Unmount without joining the fuser session thread.
///
/// fuser 0.18's `BackgroundSession::umount_and_join` can wait forever when
/// `AutoUnmount` owns the mount (W13a known issue). The external commands do
/// the same job from outside the session and let the session thread observe
/// the closed FUSE device on its own:
///
/// 1. `fusermount3 -u <mountpoint>` (bounded, killed at the deadline);
/// 2. `fusermount3 -uz <mountpoint>`;
/// 3. `umount2(MNT_DETACH)`.
///
/// The session handle is leaked only after the mountpoint is gone, so its
/// `Drop` cannot start a second, blocking unmount. If every step fails the
/// handle stays in `mount`, which is exactly what DEGRADED_RO needs.
#[cfg(feature = "fuse")]
async fn unmount(
    mount: &mut Option<MountHandle>,
    mountpoint: &Path,
) -> Result<(), lifecycle::UnmountError> {
    if !is_mounted(mountpoint) {
        if let Some(session) = mount.take() {
            std::mem::forget(session);
        }
        return Ok(());
    }

    for flag in ["-u", "-uz"] {
        if fusermount_step(flag, mountpoint).await && !is_mounted(mountpoint) {
            if let Some(session) = mount.take() {
                std::mem::forget(session);
            }
            return Ok(());
        }
    }

    if detach_step(mountpoint).await && !is_mounted(mountpoint) {
        if let Some(session) = mount.take() {
            std::mem::forget(session);
        }
        return Ok(());
    }

    Err(lifecycle::UnmountError::Exhausted)
}

#[cfg(not(feature = "fuse"))]
async fn unmount(
    _mount: &mut Option<MountHandle>,
    _mountpoint: &Path,
) -> Result<(), lifecycle::UnmountError> {
    Ok(())
}

#[cfg(feature = "fuse")]
async fn fusermount_step(flag: &'static str, mountpoint: &Path) -> bool {
    let mountpoint = mountpoint.to_path_buf();
    tokio::task::spawn_blocking(move || fusermount_blocking(flag, &mountpoint))
        .await
        .unwrap_or(false)
}

#[cfg(feature = "fuse")]
fn fusermount_blocking(flag: &'static str, mountpoint: &Path) -> bool {
    let mut child = match std::process::Command::new("fusermount3")
        .arg(flag)
        .arg(mountpoint)
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            tracing::warn!(%error, flag, "fusermount3 could not be started");
            return !is_mounted(mountpoint);
        }
    };
    let deadline = Instant::now() + EXTERNAL_UNMOUNT_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => return !is_mounted(mountpoint),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                tracing::warn!(flag, "fusermount3 timed out");
                return !is_mounted(mountpoint);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                tracing::warn!(%error, flag, "fusermount3 wait failed");
                return !is_mounted(mountpoint);
            }
        }
    }
}

#[cfg(feature = "fuse")]
async fn detach_step(mountpoint: &Path) -> bool {
    let mountpoint = mountpoint.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let result = rustix::mount::unmount(&mountpoint, rustix::mount::UnmountFlags::DETACH);
        if let Err(error) = result {
            tracing::warn!(%error, "umount2(MNT_DETACH) failed");
        }
        !is_mounted(&mountpoint)
    })
    .await
    .unwrap_or(false)
}

/// Map a frame-boundary error to the connection error a JOIN reports.
fn conn_error(error: crate::protocol::ProtocolError) -> ClientError {
    ClientError::Connection(ConnError::Protocol(error))
}

/// Read the verdict out of a `RELAY{CTRL}` body.
///
/// A malformed `JOIN_ACCEPT` is a rejection, never a silent "keep waiting":
/// the only safe reading of an answer this client cannot parse is that the
/// exchange failed.
fn join_verdict_from_relay(relay: crate::protocol::Relay<'_>) -> Option<JoinVerdict> {
    match relay.sub {
        RelaySub::JoinAccept => Some(
            relay
                .fields
                .get(fid::F_KEY_ENTRIES)
                .and_then(decode_key_entries)
                .map_or(
                    JoinVerdict::Rejected(PROOF_RESULT_INVALID),
                    JoinVerdict::Accepted,
                ),
        ),
        RelaySub::JoinFail => Some(JoinVerdict::Rejected(
            relay
                .fields
                .u8(fid::F_PROOF_RESULT)
                .ok()
                .flatten()
                .unwrap_or(PROOF_RESULT_INVALID),
        )),
        _ => None,
    }
}

/// `RELAY{CTRL, JOIN_PROOF}` body (50 §3.2).
fn encode_join_proof(
    sealed: &[u8],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    own: &KeyAnnounce,
) -> Result<Vec<u8>, ClientError> {
    let mut writer = WcpWriter::new();
    writer.u8(fid::F_SUB_KIND, RelaySub::JoinProof.as_u8());
    writer.bytes(fid::F_CLIENT_NONCE, client_nonce);
    writer.bytes(fid::F_SERVER_NONCE, server_nonce);
    writer.bytes(fid::F_PROOF, sealed);
    writer.bytes(
        fid::F_KEY_ENTRIES,
        &encode_key_entries(std::slice::from_ref(own)),
    );
    writer
        .finish()
        .map_err(|error| ClientError::Join(format!("join proof body: {error}")))
}

/// `RELAY{CTRL, JOIN_ACCEPT}` body: every key the verifier knows.
fn encode_join_accept(entries: &[KeyAnnounce]) -> Result<Vec<u8>, ClientError> {
    let mut writer = WcpWriter::new();
    writer.u8(fid::F_SUB_KIND, RelaySub::JoinAccept.as_u8());
    writer.bytes(fid::F_KEY_ENTRIES, &encode_key_entries(entries));
    writer
        .finish()
        .map_err(|error| ClientError::Join(format!("join accept body: {error}")))
}

/// `RELAY{CTRL, JOIN_FAIL}` body: why the proof was refused.
fn encode_join_fail(result: u8) -> Result<Vec<u8>, ClientError> {
    let mut writer = WcpWriter::new();
    writer.u8(fid::F_SUB_KIND, RelaySub::JoinFail.as_u8());
    writer.u8(fid::F_PROOF_RESULT, result);
    writer
        .finish()
        .map_err(|error| ClientError::Join(format!("join fail body: {error}")))
}

/// Serialize key entries in the fixed [`KEY_ENTRY_LEN`] record layout.
fn encode_key_entries(entries: &[KeyAnnounce]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * KEY_ENTRY_LEN);
    for entry in entries {
        out.extend_from_slice(entry.client.as_bytes());
        out.extend_from_slice(&entry.epoch.get().to_le_bytes());
        out.extend_from_slice(entry.public.as_bytes());
        out.extend_from_slice(entry.self_sig.as_bytes());
    }
    out
}

/// Parse [`encode_key_entries`] output. The binding is checked later by
/// [`KeyDirectory::trust`], never here.
fn decode_key_entries(bytes: &[u8]) -> Option<Vec<KeyAnnounce>> {
    if bytes.len() % KEY_ENTRY_LEN != 0 {
        return None;
    }
    let mut entries = Vec::with_capacity(bytes.len() / KEY_ENTRY_LEN);
    for chunk in bytes.chunks_exact(KEY_ENTRY_LEN) {
        let mut client = [0u8; ClientId::LEN];
        client.copy_from_slice(&chunk[..ClientId::LEN]);
        let mut epoch = [0u8; 4];
        epoch.copy_from_slice(&chunk[ClientId::LEN..ClientId::LEN + 4]);
        let public =
            PublicKey::from_slice(&chunk[ClientId::LEN + 4..ClientId::LEN + 4 + PublicKey::LEN])
                .ok()?;
        let self_sig = Signature::from_slice(&chunk[ClientId::LEN + 4 + PublicKey::LEN..]).ok()?;
        entries.push(KeyAnnounce {
            client: ClientId::from_bytes(client),
            epoch: KeyEpoch(u32::from_le_bytes(epoch)),
            public,
            self_sig,
            prev_sig: None,
        });
    }
    Some(entries)
}

/// Plaintext `SYNC_END{Done}` that closes one relay session.
///
/// The server removes the slot and resets the origin's retry count; leaving
/// the slot open would make the next session look like a source change.
fn sync_end_frame(session: SessionId) -> Result<FrameBuf, ClientError> {
    let body = crate::protocol::SyncEnd {
        reason: crate::protocol::SyncEndReason::Done,
        detail: None,
    }
    .encode()
    .map_err(|error| ClientError::Join(format!("join relay close body: {error}")))?;
    let prefix = Prefix::Route(RoutePrefix::new(session, StreamId::CTRL, 0, 0));
    let mut header = FrameHeader::new(MsgType::SYNC_END, Flags::ROUTED, 0, Seq::UNSEQUENCED);
    header.len = (RoutePrefix::ENCODED_LEN + body.len()) as u32;
    Ok(FrameBuf::new(header, prefix, body))
}

/// Seal one `RELAY{CTRL}` body for `session`.
fn seal_relay(
    ring: &KeyRing,
    nonces: &NonceMinter,
    session: SessionId,
    body: &[u8],
) -> Result<FrameBuf, ClientError> {
    let prefix = Prefix::Route(RoutePrefix::new(session, StreamId::CTRL, 0, 0));
    let mut header = FrameHeader::new(
        MsgType::RELAY,
        Flags::ENC.with(Flags::ROUTED),
        0,
        Seq::UNSEQUENCED,
    );
    let sealed = Sealer::new(ring, nonces)
        .seal(&mut header, &prefix, body)
        .map_err(|error| ClientError::Join(format!("relay seal: {error}")))?;
    Ok(FrameBuf::new(header, prefix, sealed.into_vec()))
}

/// Answer one incoming `RELAY{CTRL, JOIN_PROOF}`.
///
/// Returns the frame to send back on the same relay session, or `None` when
/// the frame is not a join proof. A body that does not open under this
/// client's key ring is not answered: the sender does not hold the cluster
/// key, so it could not read an answer anyway. The joining client fails closed
/// on its own deadline.
fn answer_join_proof(
    frame: &FrameBuf,
    auth: &JoinAuth,
    ring: &KeyRing,
    keys: &Mutex<KeyDirectory>,
    cluster: &ClusterId,
) -> Option<FrameBuf> {
    let route = frame.prefix.as_route()?;
    if route.stream != StreamId::CTRL || route.chunk_index != 0 || route.total_chunks != 0 {
        return None;
    }
    let plaintext = Opener::new(ring)
        .open(&frame.header, &frame.prefix, &frame.body)
        .ok()?;
    let crate::protocol::Message::Relay(relay) =
        decode_sealed(MsgType::RELAY, plaintext.as_slice(), &Limits::default()).ok()?
    else {
        return None;
    };
    if relay.sub != RelaySub::JoinProof {
        return None;
    }
    let client_nonce = relay.fields.fixed::<32>(fid::F_CLIENT_NONCE).ok()??;
    let server_nonce = relay.fields.fixed::<32>(fid::F_SERVER_NONCE).ok()??;
    let sealed = relay.fields.get(fid::F_PROOF)?;
    let mut announced = relay
        .fields
        .get(fid::F_KEY_ENTRIES)
        .and_then(decode_key_entries)?;
    if announced.len() != 1 {
        return None;
    }
    let announced = announced.pop()?;

    let own = KeyAnnounce::sign(
        auth.signing().as_ref(),
        cluster,
        auth.signing().key_epoch(),
        None,
    );
    let (result, entries) = {
        let mut directory = keys.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = directory.trust(&own);
        match Proof::open(&auth.master, cluster, &client_nonce, &server_nonce, sealed) {
            Ok(proof)
                if proof.client_id() == announced.client
                    && proof.public_key() == announced.public.as_bytes() =>
            {
                match directory.trust(&announced) {
                    Ok(_) => (
                        0u8,
                        directory
                            .iter()
                            .map(|entry| KeyAnnounce {
                                client: entry.client,
                                epoch: entry.epoch,
                                public: entry.public,
                                self_sig: entry.self_sig,
                                prev_sig: None,
                            })
                            .collect::<Vec<_>>(),
                    ),
                    Err(_) => (PROOF_RESULT_KEY_REJECTED, Vec::new()),
                }
            }
            Ok(_) => (PROOF_RESULT_KEY_MISMATCH, Vec::new()),
            Err(_) => (PROOF_RESULT_PROOF_INVALID, Vec::new()),
        }
    };
    let body = if result == 0 {
        encode_join_accept(&entries).ok()?
    } else {
        encode_join_fail(result).ok()?
    };
    seal_relay(ring, &auth.nonces(), route.session_id, &body).ok()
}

#[allow(clippy::too_many_arguments)]
fn spawn_replay_pump(
    mut replayer: Replayer,
    mut rx: mpsc::Receiver<DownlinkItem>,
    backing: Arc<dyn ReplayBacking>,
    epoch: u64,
    ring: Arc<KeyRing>,
    data: Arc<DataCache>,
    counters: Arc<Counters>,
    status: Arc<StatusState>,
    events: mpsc::Sender<Event>,
    verify: Option<VerifyContext>,
    link: Option<Arc<RelaySyncLink>>,
    holder: Option<Arc<Holder>>,
    backlog: usize,
) {
    tokio::spawn(async move {
        let opener = Opener::new(&ring);
        status.epoch.store(epoch, Ordering::Relaxed);
        let start = Instant::now();
        // Frames the JOIN read are the first `backlog` items on this channel.
        // They are counted so the pump can record that it consumed them; the
        // watermark they carry is published before the uplink can send its
        // first `PING` (see `Action::OpenWriteGate`).
        let mut consumed = 0usize;
        while let Some(item) = rx.recv().await {
            consumed += 1;
            if consumed == backlog {
                status.publish(&replayer);
            }
            let frame = match item {
                DownlinkItem::StreamData(frame) => {
                    if let Some(link) = &link {
                        match link.deliver_stream(&frame).await {
                            Ok(true) => continue,
                            Ok(false) => {}
                            Err(error) => {
                                tracing::warn!(%error, "relay block stream rejected");
                                continue;
                            }
                        }
                    }
                    if let Err(error) = data.push(&frame, &opener) {
                        tracing::warn!(%error, "STREAM_DATA rejected");
                    }
                    continue;
                }
                DownlinkItem::Relay(frame) => {
                    // JOIN_PROOF is control-plane: answer it before any
                    // holder work. A block stream can take seconds, and the
                    // joining client would wait that long for its proof.
                    if let Some(context) = &verify {
                        if let Some(reply) = answer_join_proof(
                            &frame,
                            &context.auth,
                            &ring,
                            &context.keys,
                            &context.cluster,
                        ) {
                            // Wait for the bounded queue instead of dropping a
                            // JOIN_ACCEPT: the joining client is kicked if its
                            // proof answer never reaches the uplink.
                            if context.control.send(reply).await.is_err() {
                                tracing::warn!("join proof answer dropped: uplink closed");
                            }
                            continue;
                        }
                    }
                    if let Some(link) = &link {
                        if link.deliver(&frame) {
                            continue;
                        }
                    }
                    if let Some(holder) = &holder {
                        // Holder requests build or stream a view. Run them
                        // off the pump so the next RELAY frame (including a
                        // proof) is not delayed behind a block stream.
                        let holder = Arc::clone(holder);
                        tokio::spawn(async move {
                            match holder.deliver(&frame).await {
                                Ok(true) | Ok(false) => {}
                                Err(error) => {
                                    tracing::warn!(%error, "holder rejected relay request");
                                }
                            }
                        });
                    }
                    continue;
                }
                DownlinkItem::Leave { frame, leave } => {
                    // A `LEAVE` occupies a sequence like any operation. It
                    // must pass through the replayer, or `applied_seq` stays
                    // behind and every later frame looks like a gap.
                    match replayer.on_leave(
                        frame.header.seq,
                        epoch,
                        &leave,
                        start.elapsed(),
                        backing.as_ref(),
                        data.as_ref(),
                    ) {
                        Ok(progress) => {
                            note_replay_step(&replayer, &counters, &status, &progress);
                        }
                        Err(error) => {
                            tracing::error!(
                                %error,
                                seq = frame.header.seq.get(),
                                "LEAVE replay stopped"
                            );
                            status.publish(&replayer);
                            let _ = events.send(replay_fatal(&counters, &error)).await;
                            return;
                        }
                    }
                    continue;
                }
                DownlinkItem::Ordered(frame) => frame,
                _ => continue,
            };
            let opened = match &verify {
                Some(context) => {
                    let keys = context.keys.lock().unwrap_or_else(PoisonError::into_inner);
                    decode_ordered_verified(
                        &frame,
                        epoch,
                        &Limits::default(),
                        |header, prefix, body| {
                            opener
                                .open(header, prefix, body)
                                .map(|opened| opened.as_slice().to_vec())
                        },
                        &keys,
                    )
                }
                None => {
                    decode_ordered(&frame, epoch, &Limits::default(), |header, prefix, body| {
                        opener
                            .open(header, prefix, body)
                            .map(|opened| opened.as_slice().to_vec())
                    })
                }
            };
            let incoming = match opened {
                Ok(incoming) => incoming,
                Err(error) => {
                    match &error {
                        DownlinkError::Untrusted(_) | DownlinkError::PayloadHashMismatch => {
                            // Fail closed: the frame is dropped, nothing is
                            // applied, and `applied_seq` does not move. The
                            // session stops because no later frame may be
                            // trusted either.
                            Counters::bump(&counters.ops_rejected);
                            tracing::error!(
                                event = "untrusted",
                                %error,
                                seq = frame.header.seq.get(),
                                "ORDERED rejected: frame dropped, applied_seq unchanged"
                            );
                        }
                        _ => tracing::error!(%error, "ORDERED decode failed"),
                    }
                    let _ = events.send(Event::Fatal(FatalError::Protocol)).await;
                    return;
                }
            };
            match replayer.on_ordered(incoming, start.elapsed(), backing.as_ref(), data.as_ref()) {
                Ok(progress) => {
                    note_replay_step(&replayer, &counters, &status, &progress);
                }
                Err(error) => {
                    tracing::error!(%error, "replay stopped");
                    let event = replay_fatal(&counters, &error);
                    status.publish(&replayer);
                    let _ = events.send(event).await;
                    return;
                }
            }
        }
    });
}

/// Record one replay step in the counters and the published status.
fn note_replay_step(
    replayer: &Replayer,
    counters: &Counters,
    status: &StatusState,
    progress: &replayer::Progress,
) {
    if progress.duplicate {
        Counters::bump(&counters.ops_duplicate);
    } else {
        Counters::bump(&counters.ops_applied);
        if progress.verdict.is_err() {
            Counters::bump(&counters.ops_rejected);
        }
    }
    status.publish(replayer);
}

/// Translate a replay failure into the lifecycle event that ends the session.
fn replay_fatal(counters: &Counters, error: &replayer::Fatal) -> Event {
    match error {
        replayer::Fatal::ResyncLoop => Event::BudgetExpired,
        replayer::Fatal::Materialize { .. } => {
            Counters::bump(&counters.materialize_errors);
            Event::Fatal(FatalError::Materialize)
        }
        replayer::Fatal::Protocol(_) => Event::Fatal(FatalError::Protocol),
        replayer::Fatal::UnknownOpClass(_) => {
            Counters::bump(&counters.ops_rejected);
            Event::Fatal(FatalError::Protocol)
        }
        replayer::Fatal::Resync(_) => {
            Counters::bump(&counters.resyncs);
            Event::Fatal(FatalError::Replay)
        }
    }
}

/// No content cache: an empty-cluster JOIN needs none, and a view that needs
/// bytes must supply a real reader.
#[derive(Debug)]
struct EmptyChunks;

/// One resolved remote view plus the watermarks the JOIN records.
#[derive(Debug)]
struct ResolvedView {
    /// The authoritative view applied by cluster-wins.
    view: RemoteView,
    /// Content source for the view.
    chunks: Arc<dyn ChunkReader>,
    /// Peer delta source, when the view needs one.
    delta: Option<Arc<dyn DeltaPeer>>,
    /// Watermark of the view; the replayer starts here.
    view_seq: Seq,
    /// Watermark the snapshot installed, when one was pulled.
    covered_seq: Option<Seq>,
}

/// Reject a `WELCOME` whose declared view is not the current watermark.
///
/// The replayer must start at the view's watermark. When the server declares
/// a view at another sequence, the client cannot tell which operations the
/// view already contains; fail closed instead of replaying or deleting
/// blindly.
fn check_welcome_view(welcome: &Welcome) -> Result<(), ClientError> {
    if welcome.view_self
        && (welcome.view_holder.is_some()
            || welcome.view_seq.is_some()
            || welcome.view_session.is_some())
    {
        return Err(ClientError::Join(
            "WELCOME mixes view_self with a holder view".to_owned(),
        ));
    }
    match welcome.view_seq {
        Some(view_seq) if view_seq != welcome.current_seq => Err(ClientError::Join(format!(
            "WELCOME declares view seq {} but current seq {}; refusing to join",
            view_seq.get(),
            welcome.current_seq.get()
        ))),
        _ => Ok(()),
    }
}

/// The watermark the replayer may start at.
///
/// A declared view sequence must match the view the client built. Without a
/// declaration the view's own watermark is authoritative.
fn view_watermark(declared: Option<Seq>, view: Seq) -> Result<Seq, ClientError> {
    match declared {
        Some(declared) if declared != view => Err(ClientError::Join(format!(
            "the remote view covers seq {} but WELCOME declares view seq {}",
            view.get(),
            declared.get()
        ))),
        Some(declared) => Ok(declared),
        None => Ok(view),
    }
}

impl ChunkReader for EmptyChunks {
    fn read(&self, _kind: ChunkKind, _id: ChunkId) -> Result<Option<Vec<u8>>, SyncError> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// W13b adapter: the replay engine's identity-preserving view of PosixBacking.
// ---------------------------------------------------------------------------

impl ReplayBacking for PosixBacking {
    fn mkdir(&self, parent: InodeId, name: &OsStr, id: InodeId, mode: u32) -> Result<(), Errno> {
        let generated = BackingStore::mkdir(self, parent, name, mode)?;
        if generated != id {
            let _ = self.nodes().remove_name(parent, name);
            self.nodes().insert_link(id, parent, name, Kind::Dir)?;
        }
        Ok(())
    }

    fn create(&self, parent: InodeId, name: &OsStr, id: InodeId, mode: u32) -> Result<(), Errno> {
        BackingStore::create(self, parent, name, id, mode)
    }

    fn symlink(
        &self,
        parent: InodeId,
        name: &OsStr,
        id: InodeId,
        target: &Path,
    ) -> Result<(), Errno> {
        self.symlink_with_id(parent, name, target, id).map(|_| ())
    }

    fn unlink(&self, parent: InodeId, name: &OsStr) -> Result<(), Errno> {
        BackingStore::unlink(self, parent, name)
    }

    fn rmdir(&self, parent: InodeId, name: &OsStr) -> Result<(), Errno> {
        let path = self
            .nodes()
            .path_of(parent)
            .ok_or(Errno::ENOENT)?
            .join(name);
        self.root().rmdir_at(&path)?;
        let _ = self.nodes().remove_name(parent, name);
        Ok(())
    }

    fn rename(&self, from: (InodeId, &OsStr), to: (InodeId, &OsStr)) -> Result<(), Errno> {
        BackingStore::rename(self, from, to, RenameFlags(0))
    }

    fn link(&self, id: InodeId, parent: InodeId, name: &OsStr) -> Result<(), Errno> {
        BackingStore::link(self, id, parent, name)
    }

    fn write_at(&self, id: InodeId, off: u64, data: &[u8]) -> Result<(), Errno> {
        BackingStore::write_at(self, id, off, data).map(|_| ())
    }

    fn truncate(&self, id: InodeId, size: u64) -> Result<(), Errno> {
        BackingStore::truncate(self, id, size)
    }

    fn set_attr(&self, id: InodeId, delta: &AttrDelta) -> Result<(), Errno> {
        BackingStore::set_attr(self, id, delta)
    }

    fn apply_effect(&self, id: InodeId, effect: &crate::store::Effect) -> Result<(), Errno> {
        BackingStore::apply_effect(self, id, effect)
    }
}

/// In-memory signer used by [`Client::run`] when the caller supplies no W7
/// identity. It claims the configured client id and signs with a per-process
/// key; verification belongs to W4 and is not performed by this build.
struct LocalIdentity {
    inner: MemoryIdentity,
    client_id: crate::protocol::ClientId,
}

impl LocalIdentity {
    fn new(client_id: crate::protocol::ClientId) -> Self {
        let mut seed = [0u8; 32];
        seed[..16].copy_from_slice(client_id.as_bytes());
        seed[16..].copy_from_slice(client_id.as_bytes());
        Self {
            inner: MemoryIdentity::from_seed(
                ClusterId::from_bytes([0u8; 16]),
                KeyEpoch::INITIAL,
                seed,
            ),
            client_id,
        }
    }
}

impl Identity for LocalIdentity {
    fn client_id(&self) -> crate::protocol::ClientId {
        self.client_id
    }

    fn public_key(&self) -> crate::protocol::identity::PublicKey {
        self.inner.public_key()
    }

    fn key_epoch(&self) -> KeyEpoch {
        self.inner.key_epoch()
    }

    fn sign_bytes(&self, message: &[u8]) -> crate::protocol::identity::Signature {
        self.inner.sign_bytes(message)
    }
}

impl std::fmt::Debug for LocalIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalIdentity")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::protocol::ClientId;

    fn config() -> Config {
        Config {
            endpoint: Endpoint::parse("http://127.0.0.1:1/sync").expect("endpoint"),
            mountpoint: std::path::PathBuf::from("/tmp/syncmount-w12-not-mounted"),
            client_id: ClientId::from_bytes([7; 16]),
            instance: InstanceId(1),
            mount_id: "w12".to_string(),
            tuning: Tuning::default(),
            password: PasswordSource::Tty,
            run_dir: std::path::PathBuf::from("/tmp"),
            allow_empty_view: false,
        }
    }

    /// 31:M3-1 / W17: a JOIN with a snapshot pulls and installs it through
    /// the W14 ports, then reads the manifest for the local diff.
    #[tokio::test]
    async fn i_client_join_pulls_snapshot_and_manifest() {
        use crate::protocol::messages::{JoinState, ResyncMode, WelcomeLimits};
        use crate::protocol::{Caps, ProtoVersion};
        use crate::sync::ChunkReader;
        use crate::sync::test_support::{
            CLUSTER, FakeLink, FakeState, MemChunks, MemTree, holder_views, make_image, ports,
            publish_snapshot,
        };

        let image = make_image(4096, &[("a", 1)], 1024);
        let chunks = MemChunks::new();
        let link = FakeLink::new(chunks.clone());
        let reference = publish_snapshot(&image, chunks.as_ref(), link.as_ref()).await;
        let (manifest, blockmap) = holder_views(&image, chunks.as_ref());
        *link.manifest.lock().unwrap() = Some(manifest);
        *link.blockmap.lock().unwrap() = Some(blockmap);
        let state = FakeState::new(0, image);
        let mut sync_ports = ports(state, chunks.clone(), link, MemTree::new());
        sync_ports.cache = Some(chunks.clone() as Arc<dyn ChunkReader>);

        let client = Client::new(config())
            .with_cluster(CLUSTER)
            .with_sync_ports(sync_ports);
        let welcome = Welcome {
            proto: ProtoVersion::CURRENT,
            caps: Caps::REQUIRED,
            epoch: 7,
            current_seq: Seq(9000),
            client_id: ClientId::from_bytes([7; 16]),
            resync: ResyncMode::ManifestDiff,
            limits: WelcomeLimits {
                max_frame: 1 << 20,
                credit_bytes: 1 << 20,
                session_ttl_s: 60,
                max_sessions: 4,
            },
            server_time: 0,
            server_nonce: [0u8; 32],
            join_state: JoinState::Accepted,
            session_id: None,
            snapshot_ref: Some(reference),
            view_holder: None,
            view_seq: None,
            view_session: None,
            view_self: false,
        };
        let resolved = client.remote_view(&welcome).await.unwrap();
        assert_eq!(resolved.view_seq, Seq(4096));
        assert_eq!(resolved.covered_seq, Some(Seq(4096)));
        assert_eq!(resolved.view.manifest.at_seq, Seq(4096));
        assert_eq!(resolved.view.manifest.len(), 1);
    }

    #[test]
    fn u_signing_key_is_send_sync_for_uplink_task() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<crate::crypto::SigningKey>();
    }

    fn welcome_at(current_seq: Seq) -> Welcome {
        use crate::protocol::messages::{JoinState, ResyncMode, WelcomeLimits};
        use crate::protocol::{Caps, ProtoVersion};
        Welcome {
            proto: ProtoVersion::CURRENT,
            caps: Caps::REQUIRED,
            epoch: 7,
            current_seq,
            client_id: ClientId::from_bytes([7; 16]),
            resync: ResyncMode::ManifestDiff,
            limits: WelcomeLimits {
                max_frame: 1 << 20,
                credit_bytes: 1 << 20,
                session_ttl_s: 60,
                max_sessions: 4,
            },
            server_time: 0,
            server_nonce: [0u8; 32],
            join_state: JoinState::Accepted,
            session_id: None,
            snapshot_ref: None,
            view_holder: None,
            view_seq: None,
            view_session: None,
            view_self: false,
        }
    }

    /// A fixed remote view: the manifest and blockmap a holder would serve.
    #[derive(Debug)]
    struct FixedView {
        manifest: Manifest,
        blockmap: Blockmap,
    }

    impl JoinView for FixedView {
        fn remote(&self) -> RemoteView {
            RemoteView {
                reference: None,
                manifest: self.manifest.clone(),
                blockmap: self.blockmap.clone(),
            }
        }

        fn chunks(&self) -> Arc<dyn ChunkReader> {
            Arc::new(EmptyChunks)
        }

        fn delta(&self) -> Option<Arc<dyn DeltaPeer>> {
            None
        }
    }

    /// A positive watermark with no view is a data-loss path, not a
    /// fallback. Only an explicit opt-in may accept the empty view.
    #[tokio::test]
    async fn u_join_refuses_empty_view_above_zero() {
        let client = Client::new(config());
        let error = client
            .remote_view(&welcome_at(Seq(5)))
            .await
            .expect_err("an empty view above zero must be refused");
        match error {
            ClientError::Join(message) => {
                assert!(
                    message.contains("no view") && message.contains("delete local-only"),
                    "the refusal must state the loss: {message}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let opted_in = Client::new(config().with_allow_empty_view(true));
        let resolved = opted_in
            .remote_view(&welcome_at(Seq(5)))
            .await
            .expect("the explicit opt-in accepts the empty view");
        assert_eq!(resolved.view_seq, Seq(5));
        assert_eq!(resolved.view.manifest.len(), 0);
        assert_eq!(resolved.covered_seq, None);

        // Sequence zero is exact: no view is the correct view.
        let zero = Client::new(config())
            .remote_view(&welcome_at(Seq::UNSEQUENCED))
            .await
            .expect("watermark zero joins without an opt-in");
        assert_eq!(zero.view_seq, Seq::UNSEQUENCED);
    }

    /// The replayer starts at the view's watermark, and a WELCOME that
    /// declares another one is refused before any diff runs.
    #[test]
    fn u_join_view_watermark_must_match() {
        assert!(check_welcome_view(&welcome_at(Seq(9))).is_ok());

        let mut welcome = welcome_at(Seq(9));
        welcome.view_seq = Some(Seq(8));
        assert!(
            check_welcome_view(&welcome).is_err(),
            "view_seq must equal current_seq"
        );
        welcome.view_seq = Some(Seq(9));
        assert!(check_welcome_view(&welcome).is_ok());

        assert_eq!(view_watermark(Some(Seq(9)), Seq(9)).ok(), Some(Seq(9)));
        assert!(
            view_watermark(Some(Seq(9)), Seq(8)).is_err(),
            "the view must cover exactly the declared watermark"
        );
        assert_eq!(view_watermark(None, Seq(4)).ok(), Some(Seq(4)));
    }

    /// A sparse/placeholder blockmap has `Some(vec![])` for a file with
    /// blocks; the pull gate must treat that as missing, not as "complete".
    #[test]
    fn u_blockmap_pull_includes_placeholder_maps() {
        let dir = tempfile::TempDir::new().expect("root");
        std::fs::create_dir(dir.path().join("file")).expect("dir");
        let root = Arc::new(RootFd::open_before_mount(dir.path()).expect("root fd"));
        let cluster = ClusterId::from_bytes([0x31; 16]);
        let tree = FsTree::new(Arc::clone(&root), cluster);
        let block = ChunkId::of_plaintext(b"x");
        let remote = Manifest::try_new(
            Seq(1),
            vec![crate::sync::manifest::Entry::file(
                "file",
                InodeId::from_bytes([1; 16]),
                0o644,
                1000,
                1000,
                1,
                0,
                &[block],
            )],
        )
        .expect("manifest");
        let plan = crate::sync::manifest::diff::plan(None, &remote, &tree, cluster).expect("plan");
        assert!(
            plan.transfers()
                .any(|item| item.kind == crate::sync::DiffKind::TypeReplace)
        );

        let placeholder = Blockmap::new(Seq(1), vec![0], Vec::new()).expect("placeholder");
        assert!(
            needs_blockmap_pull(&plan, &remote, &placeholder),
            "a placeholder map with an empty block list must trigger a pull"
        );

        let complete = Blockmap::new(Seq(1), vec![0], vec![block]).expect("complete");
        assert!(!needs_blockmap_pull(&plan, &remote, &complete));
    }

    /// A blockmap index from another sequence or file set must be refused
    /// before the diff applies blocks to the wrong paths.
    #[test]
    fn u_blockmap_index_must_match_manifest() {
        let manifest = Manifest::try_new(
            Seq(4),
            vec![crate::sync::manifest::Entry::file(
                "a",
                InodeId::from_bytes([1; 16]),
                0o644,
                1000,
                1000,
                0,
                0,
                &[],
            )],
        )
        .expect("manifest");
        let matching = crate::sync::manifest::BlockmapIndex {
            at_seq: Seq(4),
            block_total: 0,
            file_first_block: vec![0],
            data_parts: Vec::new(),
        };
        assert!(blockmap_index_matches(&matching, &manifest));

        let wrong_seq = crate::sync::manifest::BlockmapIndex {
            at_seq: Seq(5),
            block_total: 0,
            file_first_block: vec![0],
            data_parts: Vec::new(),
        };
        assert!(!blockmap_index_matches(&wrong_seq, &manifest));

        let wrong_files = crate::sync::manifest::BlockmapIndex {
            at_seq: Seq(4),
            block_total: 0,
            file_first_block: vec![0, 0],
            data_parts: Vec::new(),
        };
        assert!(!blockmap_index_matches(&wrong_files, &manifest));
    }

    /// A self view reloads only a manifest whose epoch matches the WELCOME
    /// and whose sequence is the current one or exactly one behind it. The
    /// one-step gap is a `LEAVE` that a crash left unapplied; a wider gap is
    /// a real hole and stays fatal before any file is touched.
    #[tokio::test]
    async fn u_self_view_requires_matching_manifest() {
        let dir = tempfile::TempDir::new().expect("root");
        let root = Arc::new(RootFd::open_before_mount(dir.path()).expect("root fd"));
        let cluster = ClusterId::from_bytes([0x44; 16]);
        let manifest = Manifest::new(
            Seq(3),
            vec![crate::sync::manifest::Entry::dir(
                "d",
                InodeId(2),
                0o755,
                1000,
                1000,
                0,
            )],
        );
        LocalManifest {
            cluster_id: cluster,
            at_seq: Seq(3),
            epoch: 9,
            manifest,
        }
        .store(root.as_ref())
        .expect("store manifest");

        let mut client = Client::new(config()).with_cluster(cluster);
        client.root = Some(Arc::clone(&root));
        let mut welcome = welcome_at(Seq(3));
        welcome.epoch = 9;
        welcome.view_self = true;

        let resolved = client.remote_view(&welcome).await.expect("self view");
        assert_eq!(resolved.view_seq, Seq(3));
        assert_eq!(resolved.view.manifest.len(), 1);
        assert_eq!(
            resolved.view.blockmap.file_blocks(0),
            Some(Vec::new()),
            "the self-view blockmap has offsets but no block ids"
        );

        let mut wrong_epoch = welcome;
        wrong_epoch.epoch = 10;
        assert!(client.remote_view(&wrong_epoch).await.is_err());

        // One sequence behind: the missing frame is a `LEAVE`. The view still
        // starts at the server watermark so the replayer skips it.
        let mut one_behind = welcome;
        one_behind.current_seq = Seq(4);
        let resolved = client
            .remote_view(&one_behind)
            .await
            .expect("a one-sequence gap is a LEAVE");
        assert_eq!(resolved.view_seq, Seq(4));
        assert_eq!(resolved.view.manifest.at_seq, Seq(3));

        // Two behind: a real hole. Refuse before the diff.
        let mut two_behind = welcome;
        two_behind.current_seq = Seq(5);
        assert!(client.remote_view(&two_behind).await.is_err());

        std::fs::remove_file(dir.path().join(crate::store::MANIFEST_FILE))
            .expect("remove manifest");
        assert!(client.remote_view(&welcome).await.is_err());
    }

    /// A one-sequence gap is a `LEAVE` the crash left unapplied. The diff is
    /// still exact, the files survive, and the report starts the replayer at
    /// the server watermark so the missing `LEAVE` is skipped.
    #[tokio::test]
    async fn u_self_view_accepts_one_leave_gap() {
        let dir = tempfile::TempDir::new().expect("root");
        std::fs::write(dir.path().join("file.txt"), b"").expect("write");
        let root = Arc::new(RootFd::open_before_mount(dir.path()).expect("root fd"));
        let cluster = ClusterId::from_bytes([0x48; 16]);
        let attr = root
            .stat_at(std::path::Path::new("file.txt"), false)
            .expect("stat");
        let mtime_ns = u64::try_from(attr.mtime.sec)
            .unwrap_or(0)
            .saturating_mul(1_000_000_000)
            .saturating_add(u64::try_from(attr.mtime.nsec).unwrap_or(0));
        let manifest = Manifest::new(
            Seq(3),
            vec![crate::sync::manifest::Entry::file(
                "file.txt",
                InodeId(2),
                attr.perm(),
                attr.uid,
                attr.gid,
                attr.size,
                mtime_ns,
                &[ChunkId::of_plaintext(b"data")],
            )],
        );
        LocalManifest {
            cluster_id: cluster,
            at_seq: Seq(3),
            epoch: 9,
            manifest,
        }
        .store(root.as_ref())
        .expect("store manifest");

        let mut client = Client::new(config()).with_cluster(cluster);
        client.root = Some(Arc::clone(&root));
        let mut welcome = welcome_at(Seq(4));
        welcome.epoch = 9;
        welcome.view_self = true;
        let report = client
            .cluster_wins(&welcome)
            .await
            .expect("one-step gap is a LEAVE");
        assert_eq!(report.at_seq, Seq(3));
        assert_eq!(report.view_seq, Seq(4));
        assert_eq!(report.counts.transfers(), 0);
        assert_eq!(report.counts.local_only, 0);
        assert_eq!(
            std::fs::read(dir.path().join("file.txt")).expect("read"),
            b""
        );
    }

    /// A restart reports the applied manifest so the server can grant a self
    /// view. Without a readable manifest the JOIN keeps the first-start
    /// watermark and the old empty-view path.
    #[tokio::test]
    async fn u_join_watermark_reports_local_manifest() {
        let dir = tempfile::TempDir::new().expect("root");
        let root = Arc::new(RootFd::open_before_mount(dir.path()).expect("root fd"));
        let cluster = ClusterId::from_bytes([0x49; 16]);
        let mut client = Client::new(config()).with_cluster(cluster);
        assert_eq!(
            client.join_watermark(),
            (Seq::UNSEQUENCED, 0),
            "no root keeps the first-start watermark"
        );
        client.root = Some(Arc::clone(&root));
        assert_eq!(
            client.join_watermark(),
            (Seq::UNSEQUENCED, 0),
            "no manifest keeps the first-start watermark"
        );
        LocalManifest {
            cluster_id: cluster,
            at_seq: Seq(3),
            epoch: 9,
            manifest: Manifest::new(Seq(3), Vec::new()),
        }
        .store(root.as_ref())
        .expect("store manifest");
        assert_eq!(
            client.join_watermark(),
            (Seq(3), 9),
            "a clean unmount's manifest is the JOIN watermark"
        );
    }

    /// A self view with a local-only path must refuse before the diff applies
    /// anything; the path survives.
    #[tokio::test]
    async fn u_self_view_refuses_local_only_before_apply() {
        let dir = tempfile::TempDir::new().expect("root");
        std::fs::write(dir.path().join("local.txt"), b"keep").expect("write");
        let root = Arc::new(RootFd::open_before_mount(dir.path()).expect("root fd"));
        let cluster = ClusterId::from_bytes([0x45; 16]);
        LocalManifest {
            cluster_id: cluster,
            at_seq: Seq::UNSEQUENCED,
            epoch: 7,
            manifest: Manifest::new(Seq::UNSEQUENCED, Vec::new()),
        }
        .store(root.as_ref())
        .expect("store manifest");

        let mut client = Client::new(config()).with_cluster(cluster);
        client.root = Some(Arc::clone(&root));
        let mut welcome = welcome_at(Seq::UNSEQUENCED);
        welcome.view_self = true;
        let error = client
            .cluster_wins(&welcome)
            .await
            .expect_err("local-only must be refused");
        assert!(matches!(error, ClientError::Join(_)), "{error:?}");
        assert_eq!(
            std::fs::read(dir.path().join("local.txt")).expect("read"),
            b"keep"
        );
    }

    /// A self view is a complete view, not a missing one: it must not enter
    /// the empty-view retry loop.
    #[test]
    fn u_self_view_does_not_retry() {
        let client = Client::new(config());
        let mut welcome = welcome_at(Seq(5));
        welcome.view_self = true;
        assert!(!client.join_wants_view(&welcome));
    }

    /// The clean-unmount persistence writes the applied sequence and the
    /// current disk manifest, so the next self view can load it.
    #[tokio::test]
    async fn u_persist_manifest_then_self_view_reloads() {
        let dir = tempfile::TempDir::new().expect("root");
        std::fs::write(dir.path().join("file.txt"), b"data").expect("write");
        let root = Arc::new(RootFd::open_before_mount(dir.path()).expect("root fd"));
        let cluster = ClusterId::from_bytes([0x46; 16]);
        let store =
            Arc::new(VerifiedChunkStore::open(Arc::clone(&root), [0x42; 32]).expect("chunk store"));
        let ring = Arc::new(KeyRing::derive(&[0x51; 32], &cluster).expect("ring"));
        let (tx, _rx) = mpsc::channel(8);
        let holder = Arc::new(Holder::new(
            Arc::clone(&root),
            store,
            ring,
            cluster,
            Seq(1),
            Arc::new(tx),
        ));

        let mut client = Client::new(config()).with_cluster(cluster);
        client.root = Some(Arc::clone(&root));
        client.holder = Some(holder);
        let status = StatusState::default();
        status.applied.store(1, Ordering::Relaxed);
        status.epoch.store(7, Ordering::Relaxed);
        persist_manifest(&client, &status).await;

        let cache = LocalManifest::load(root.as_ref(), cluster).expect("persisted manifest");
        assert_eq!(cache.at_seq, Seq(1));
        assert_eq!(cache.epoch, 7);
        assert!(cache.manifest.find("file.txt").is_some());

        let mut welcome = welcome_at(Seq(1));
        welcome.epoch = 7;
        welcome.view_self = true;
        let resolved = client.remote_view(&welcome).await.expect("reload");
        assert_eq!(resolved.view.manifest.len(), cache.manifest.len());
    }

    /// Only a missing view above zero triggers the backoff. A declared view,
    /// a snapshot, watermark zero and the explicit opt-in all proceed.
    #[test]
    fn u_join_retries_only_without_a_view() {
        let client = Client::new(config());
        assert!(client.join_wants_view(&welcome_at(Seq(5))));
        assert!(!client.join_wants_view(&welcome_at(Seq::UNSEQUENCED)));

        let mut declared = welcome_at(Seq(5));
        declared.view_seq = Some(Seq(5));
        assert!(!client.join_wants_view(&declared));

        let opted_in = Client::new(config().with_allow_empty_view(true));
        assert!(!opted_in.join_wants_view(&welcome_at(Seq(5))));
    }

    /// A `LEAVE` is a sequenced broadcast: B's pump must replay it, or
    /// `applied_seq` stays behind and every later frame looks like a gap.
    #[tokio::test]
    async fn u_leave_advances_replay_watermark() {
        use crate::protocol::messages::Leave;

        let root = tempfile::TempDir::new().expect("root");
        let backing: Arc<dyn ReplayBacking> = Arc::new(PosixBacking::new(
            RootFd::open_before_mount(root.path()).expect("root fd"),
        ));
        let ring = Arc::new(
            KeyRing::derive(&[0x51; 32], &ClusterId::from_bytes([0x31; 16])).expect("key ring"),
        );
        let counters = Arc::new(Counters::default());
        let status = Arc::new(StatusState::default());
        let (events, _event_rx) = mpsc::channel(8);
        let (tx, rx) = mpsc::channel(8);
        let replayer = Replayer::new(
            ClientId::from_bytes([7; 16]),
            Seq::UNSEQUENCED,
            7,
            &Tuning::default(),
            Arc::new(PendingOverlay::default()),
        );
        spawn_replay_pump(
            replayer,
            rx,
            backing,
            7,
            ring,
            Arc::new(DataCache::new()),
            Arc::clone(&counters),
            Arc::clone(&status),
            events,
            None,
            None,
            None,
            0,
        );

        let leave = Leave {
            client_id: ClientId::from_bytes([9; 16]),
            reason: 0,
            last_signed_seq: 0,
        };
        let frame = FrameBuf::new(
            FrameHeader::new(MsgType::LEAVE, Flags::EMPTY, 0, Seq(1)),
            Prefix::None,
            Vec::new(),
        );
        tx.send(DownlinkItem::Leave { frame, leave })
            .await
            .expect("send LEAVE");

        let deadline = Instant::now() + Duration::from_secs(2);
        while status.applied.load(Ordering::Relaxed) != 1 {
            assert!(
                Instant::now() < deadline,
                "LEAVE did not advance applied_seq"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(counters.ops_applied.load(Ordering::Relaxed), 1);
    }

    /// A's disconnect makes the server broadcast a sequenced `LEAVE`. B's
    /// downlink and replay pump must apply it; otherwise `applied_seq` stays
    /// behind and every later frame looks like a gap.
    #[tokio::test]
    async fn i_leave_from_a_advances_b_applied() {
        let (addr, stop, task) = start_proof_server().await;
        let root = tempfile::TempDir::new().expect("root");
        let a_mnt = root.path().join("a");
        let b_mnt = root.path().join("b");
        std::fs::create_dir(&a_mnt).expect("a dir");
        std::fs::create_dir(&b_mnt).expect("b dir");
        let cluster = ClusterId::from_bytes([0x52; 16]);
        let signing_a = crate::crypto::SigningKey::from_seed(&cluster, [0x41; 32]);
        let signing_b = crate::crypto::SigningKey::from_seed(&cluster, [0x42; 32]);

        let mut a = Client::new(proof_config(addr, &a_mnt, &signing_a, "leave-a"));
        let parts_a = a.join(Seq::UNSEQUENCED, 0).await.expect("A joins");
        assert_eq!(
            parts_a.welcome.current_seq,
            Seq::UNSEQUENCED,
            "the cluster starts empty"
        );

        let mut b = Client::new(proof_config(addr, &b_mnt, &signing_b, "leave-b"));
        let parts_b = b.join(Seq::UNSEQUENCED, 0).await.expect("B joins");
        let epoch = parts_b.welcome.epoch;
        let b_id = signing_b.client_id();

        // The same wiring `run_with_identity` uses: downlink feeds the pump.
        let ConnParts {
            events,
            decoder,
            uplink,
            ..
        } = parts_b;
        let (downlink, rx, _handle) = Downlink::with_decoder(events, decoder, 64);
        let downlink_task = tokio::spawn(downlink.run());
        let _keep_uplink = uplink;

        let ring = Arc::new(KeyRing::derive(&[0x51; 32], &cluster).expect("ring"));
        let backing: Arc<dyn ReplayBacking> = Arc::new(PosixBacking::new(
            RootFd::open_before_mount(&b_mnt).expect("root fd"),
        ));
        let counters = Arc::new(Counters::default());
        let status = Arc::new(StatusState::default());
        let (events_tx, _events_rx) = mpsc::channel(8);
        let replayer = Replayer::new(
            b_id,
            Seq::UNSEQUENCED,
            epoch,
            &Tuning::default(),
            Arc::new(PendingOverlay::default()),
        );
        spawn_replay_pump(
            replayer,
            rx,
            backing,
            epoch,
            ring,
            Arc::new(DataCache::new()),
            Arc::clone(&counters),
            Arc::clone(&status),
            events_tx,
            None,
            None,
            None,
            0,
        );

        // A leaves without a `LEAVE` of its own; the server injects one.
        drop(parts_a);

        let deadline = Instant::now() + Duration::from_secs(5);
        while status.applied.load(Ordering::Relaxed) == 0 {
            assert!(
                Instant::now() < deadline,
                "B's applied_seq did not advance to A's LEAVE"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            status.applied.load(Ordering::Relaxed),
            1,
            "the injected LEAVE occupies seq 1"
        );
        assert_eq!(counters.ops_applied.load(Ordering::Relaxed), 1);

        downlink_task.abort();
        let _ = stop.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    /// A remount rebuilds `S` from the JOIN manifest. Without it the first
    /// WRITE of a path that exists on disk resolves through an empty
    /// namespace and fails with ENOENT.
    #[tokio::test]
    async fn i_remount_rebuilds_namespace_from_manifest() {
        use std::ffi::OsStr;

        use crate::client::replayer::Verdict;
        use crate::protocol::frame::OpId;
        use crate::protocol::messages::OpClass;

        let (addr, stop, task) = start_proof_server().await;
        let root = tempfile::TempDir::new().expect("root");
        let a_mnt = root.path().join("a");
        let b_mnt = root.path().join("b");
        std::fs::create_dir(&a_mnt).expect("a dir");
        std::fs::create_dir(&b_mnt).expect("b dir");
        let cluster = ClusterId::from_bytes([0x53; 16]);
        let signing_a = crate::crypto::SigningKey::from_seed(&cluster, [0x41; 32]);
        let signing_b = crate::crypto::SigningKey::from_seed(&cluster, [0x42; 32]);
        let signing_c = crate::crypto::SigningKey::from_seed(&cluster, [0x43; 32]);

        // A joins first, then "builds a file": the holder pull is the sync
        // layer's job, so the test injects the view A would serve.
        let mut a = Client::new(proof_config(addr, &a_mnt, &signing_a, "rebuild-a"));
        let parts_a = a.join(Seq::UNSEQUENCED, 0).await.expect("A joins");
        // A second client proves the cluster is not the single-client case.
        // Both leave; A's disconnect injects a sequenced LEAVE, so the
        // cluster is above zero when B remounts.
        let mut b0 = Client::new(proof_config(addr, &b_mnt, &signing_c, "rebuild-b0"));
        let parts_b0 = b0.join(Seq::UNSEQUENCED, 0).await.expect("B joins");
        drop(parts_b0);
        drop(parts_a);
        tokio::time::sleep(Duration::from_millis(500)).await;

        // The cluster is empty when B remounts, so the holder's WELCOME
        // declares view seq zero. The injected view must cover exactly that
        // watermark; a manifest at another seq is refused before the diff.
        let inode = InodeId(0x1234);
        let manifest = Manifest::new(
            Seq::UNSEQUENCED,
            vec![crate::sync::manifest::Entry::file(
                "from-a.txt",
                inode,
                0o644,
                1000,
                1000,
                0,
                0,
                &[],
            )],
        );
        let view: Arc<dyn JoinView> = Arc::new(FixedView {
            manifest,
            blockmap: Blockmap::new(Seq::UNSEQUENCED, vec![0u32; 1], Vec::new()).expect("blockmap"),
        });

        let mut b =
            Client::new(proof_config(addr, &b_mnt, &signing_b, "rebuild-b")).with_join_view(view);
        let parts_b = b.join(Seq::UNSEQUENCED, 0).await.expect("B remounts");
        assert_eq!(
            b.last_join().expect("join report").view_seq,
            Seq::UNSEQUENCED
        );
        assert_eq!(b.last_join().expect("join report").manifest.len(), 1);

        let write = Op::new(
            OpId::from_bytes([0x77; 16]),
            signing_b.client_id(),
            OpClass::WRITE,
            "/from-a.txt",
        )
        .with_attrs(OpAttrs {
            mtime_ns: 1,
            ..OpAttrs::default()
        })
        .with_body(OpBody::Write(crate::protocol::messages::DataRef {
            session: SessionId::new(1),
            total_len: 0,
            data_hash: [0; 32],
        }));
        {
            let replayer = b.replayer().expect("B has a replayer");
            let state = replayer.read_state();
            assert!(
                state
                    .lookup(InodeId::ROOT, OsStr::new("from-a.txt"))
                    .is_some(),
                "the rebuilt namespace must contain the manifest's file"
            );
            let plan = state.plan(&write);
            assert!(
                !matches!(plan.verdict, Verdict::Reject(Errno::ENOENT)),
                "WRITE of an existing path must not see ENOENT: {:?}",
                plan.verdict
            );
            assert_eq!(plan.verdict, Verdict::Apply);
        }

        drop(parts_b);
        let _ = stop.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    #[test]
    fn u_client_assembles_w12_parts() {
        let client = Client::new(config());
        assert_eq!(client.state(), State::Boot);
        assert_eq!(client.gate().check(), Err(Errno(libc::ENOTCONN)));
        assert!(client.outbox().is_empty());
        assert!(client.pending().is_empty());
        assert!(client.replayer().is_none());
    }

    #[test]
    fn u_client_gate_follows_lifecycle() {
        let mut client = Client::new(config());
        client.on(Event::Prepared(Ok(())));
        client.on(Event::LockAcquired(Ok(())));
        client.on(Event::Cleaned(Ok(())));
        client.on(Event::FuseMounted(Ok(())));
        assert_eq!(client.state(), State::Joining);
        assert_eq!(client.gate().check(), Err(Errno::EROFS));
        client.on(Event::Joined(Ok(JoinOutcome {
            epoch: 1,
            covered: 0,
        })));
        assert_eq!(client.state(), State::Steady);
        assert_eq!(client.gate().check(), Ok(()));
    }

    // -----------------------------------------------------------------------
    // W22: JOIN_PROOF handshake against a real server
    // -----------------------------------------------------------------------

    fn proof_cluster() -> ClusterId {
        ClusterId::from_bytes([0x71; 16])
    }

    fn proof_master(password: &[u8]) -> Arc<MasterKey> {
        Arc::new(MasterKey::derive_from_password(password, &proof_cluster()).expect("master key"))
    }

    fn proof_signing(seed: u8) -> Arc<SigningKey> {
        Arc::new(SigningKey::from_seed(&proof_cluster(), [seed; 32]))
    }

    fn proof_config(
        addr: std::net::SocketAddr,
        mountpoint: &std::path::Path,
        signing: &SigningKey,
        tag: &str,
    ) -> Config {
        Config {
            endpoint: Endpoint::parse(&format!("http://{addr}/")).expect("endpoint"),
            mountpoint: mountpoint.to_path_buf(),
            client_id: signing.client_id(),
            instance: InstanceId(1),
            mount_id: tag.to_owned(),
            tuning: Tuning::default(),
            password: PasswordSource::Tty,
            run_dir: mountpoint.to_path_buf(),
            allow_empty_view: false,
        }
    }

    /// A member that answers proofs exactly as the replay pump does.
    fn spawn_proof_verifier(
        parts: ConnParts,
        auth: Arc<JoinAuth>,
        ring: Arc<KeyRing>,
        keys: Arc<Mutex<KeyDirectory>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let ConnParts {
                events,
                decoder,
                uplink,
                ..
            } = parts;
            let (downlink, mut rx, _handle) = Downlink::with_decoder(events, decoder, 64);
            let mut uplink = uplink;
            let runner = tokio::spawn(downlink.run());
            while let Some(item) = rx.recv().await {
                let DownlinkItem::Relay(frame) = item else {
                    continue;
                };
                if let Some(reply) =
                    answer_join_proof(&frame, &auth, &ring, &keys, &proof_cluster())
                {
                    if uplink.send(&reply).await.is_err() {
                        break;
                    }
                }
            }
            runner.abort();
        })
    }

    async fn start_proof_server() -> (
        std::net::SocketAddr,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let server = crate::server::Server::bind(crate::server::ServeConfig::for_tests())
            .await
            .expect("server bind");
        let addr = server.local_addr().expect("server addr");
        let (stop, stop_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(server.run_with_shutdown(async {
            let _ = stop_rx.await;
        }));
        (addr, stop, task)
    }

    /// 50 §3.2 / W22: the first client of an empty cluster has nobody to
    /// prove itself to. The JOIN proceeds, the case is logged as the F16
    /// known gap, and the client trusts only its own key.
    #[tokio::test]
    async fn i_join_proof_first_client_is_trusted_without_verifier() {
        let (addr, stop, task) = start_proof_server().await;
        let root = tempfile::TempDir::new().expect("root");
        let mount = root.path().join("a");
        std::fs::create_dir(&mount).expect("mount dir");
        let cluster = proof_cluster();
        let master = proof_master(b"proof-test");
        let signing = proof_signing(0x41);
        let ring = Arc::new(KeyRing::derive(&[0x51; 32], &cluster).expect("ring"));

        let mut client = Client::new(proof_config(addr, &mount, &signing, "proof-a"))
            .with_cluster(cluster)
            .with_join_auth(Arc::clone(&master), Arc::clone(&signing));
        let parts = client
            .join_with_ring(Seq::UNSEQUENCED, 0, Some(&ring))
            .await
            .expect("the first client joins without a verifier");

        {
            let keys = client.keys().lock().unwrap_or_else(PoisonError::into_inner);
            assert_eq!(keys.len(), 1, "only this client's own key is known");
            assert!(keys.get(signing.client_id()).is_some());
        }
        drop(parts);

        let _ = stop.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    /// A member opens the proof, accepts it and returns the keys it knows;
    /// both sides end up able to verify the other's operations.
    #[tokio::test]
    async fn i_join_proof_member_accepts_and_distributes_keys() {
        let (addr, stop, task) = start_proof_server().await;
        let root = tempfile::TempDir::new().expect("root");
        let cluster = proof_cluster();
        let master = proof_master(b"proof-test");
        let ring = Arc::new(KeyRing::derive(&[0x51; 32], &cluster).expect("ring"));

        let a_mount = root.path().join("a");
        std::fs::create_dir(&a_mount).expect("a dir");
        let signing_a = proof_signing(0x41);
        let mut a = Client::new(proof_config(addr, &a_mount, &signing_a, "proof-a"))
            .with_cluster(cluster)
            .with_join_auth(Arc::clone(&master), Arc::clone(&signing_a));
        let parts_a = a
            .join_with_ring(Seq::UNSEQUENCED, 0, Some(&ring))
            .await
            .expect("A joins the empty cluster");
        let auth_a = Arc::clone(a.join_auth.as_ref().expect("join auth"));
        let verifier =
            spawn_proof_verifier(parts_a, auth_a, Arc::clone(&ring), Arc::clone(a.keys()));

        let b_mount = root.path().join("b");
        std::fs::create_dir(&b_mount).expect("b dir");
        let signing_b = proof_signing(0x42);
        let mut b = Client::new(proof_config(addr, &b_mount, &signing_b, "proof-b"))
            .with_cluster(cluster)
            .with_join_auth(Arc::clone(&master), Arc::clone(&signing_b));
        let parts_b = b
            .join_with_ring(Seq::UNSEQUENCED, 0, Some(&ring))
            .await
            .expect("B joins through a member's JOIN_ACCEPT");

        {
            let keys_b = b.keys().lock().unwrap_or_else(PoisonError::into_inner);
            assert!(keys_b.get(signing_b.client_id()).is_some(), "own key");
            assert!(
                keys_b.get(signing_a.client_id()).is_some(),
                "JOIN_ACCEPT must carry the member's key"
            );
        }
        {
            let keys_a = a.keys().lock().unwrap_or_else(PoisonError::into_inner);
            assert!(
                keys_a.get(signing_b.client_id()).is_some(),
                "the member must learn the joining client's key"
            );
        }

        drop(parts_b);
        verifier.abort();
        let _ = stop.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    /// The steady-state pump, not the test-only verifier, must answer a
    /// joining client's `JOIN_PROOF`. B only reaches STEADY if A's pump
    /// routes the RELAY frame to `answer_join_proof` and writes the answer
    /// through its uplink.
    #[tokio::test]
    async fn i_steady_pump_answers_join_proof() {
        let (addr, stop, task) = start_proof_server().await;
        let root = tempfile::TempDir::new().expect("root");
        let cluster = proof_cluster();
        let master = proof_master(b"proof-test");
        let ring = Arc::new(KeyRing::derive(&[0x51; 32], &cluster).expect("ring"));

        let a_mnt = root.path().join("a");
        std::fs::create_dir(&a_mnt).expect("a dir");
        let signing_a = proof_signing(0x41);
        let mut a = Client::new(proof_config(addr, &a_mnt, &signing_a, "pump-a"))
            .with_cluster(cluster)
            .with_join_auth(Arc::clone(&master), Arc::clone(&signing_a));
        let parts_a = a
            .join_with_ring(Seq::UNSEQUENCED, 0, Some(&ring))
            .await
            .expect("A joins the empty cluster");
        let auth_a = Arc::clone(a.join_auth.as_ref().expect("join auth"));
        let keys_a = Arc::clone(a.keys());
        let epoch_a = parts_a.welcome.epoch;
        let ConnParts {
            events,
            decoder,
            uplink,
            ..
        } = parts_a;

        let (downlink, rx, _handle) = Downlink::with_decoder(events, decoder, 64);
        let downlink_task = tokio::spawn(downlink.run());
        let (control_tx, mut control_rx) = mpsc::channel::<FrameBuf>(16);
        let mut uplink = uplink;
        let uplink_task = tokio::spawn(async move {
            while let Some(frame) = control_rx.recv().await {
                if uplink.send(&frame).await.is_err() {
                    break;
                }
            }
        });
        let backing: Arc<dyn ReplayBacking> = Arc::new(PosixBacking::new(
            RootFd::open_before_mount(&a_mnt).expect("root fd"),
        ));
        let counters = Arc::new(Counters::default());
        let status = Arc::new(StatusState::default());
        let (events_tx, _events_rx) = mpsc::channel(8);
        let replayer = Replayer::new(
            signing_a.client_id(),
            Seq::UNSEQUENCED,
            epoch_a,
            &Tuning::default(),
            Arc::new(PendingOverlay::default()),
        );
        spawn_replay_pump(
            replayer,
            rx,
            backing,
            epoch_a,
            Arc::clone(&ring),
            Arc::new(DataCache::new()),
            Arc::clone(&counters),
            Arc::clone(&status),
            events_tx,
            Some(VerifyContext {
                auth: auth_a,
                keys: keys_a,
                cluster,
                control: control_tx,
            }),
            None,
            None,
            0,
        );

        let b_mnt = root.path().join("b");
        std::fs::create_dir(&b_mnt).expect("b dir");
        let signing_b = proof_signing(0x42);
        let mut b = Client::new(proof_config(addr, &b_mnt, &signing_b, "pump-b"))
            .with_cluster(cluster)
            .with_join_auth(Arc::clone(&master), Arc::clone(&signing_b));
        let parts_b = b
            .join_with_ring(Seq::UNSEQUENCED, 0, Some(&ring))
            .await
            .expect("B joins through A's steady pump");
        assert!(b.replayer().is_some(), "B must enter STEADY");
        assert!(b.last_join().is_some(), "B must have a join report");

        drop(parts_b);
        downlink_task.abort();
        uplink_task.abort();
        let _ = stop.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    /// A JOIN that used a view relay must close that session. An open view
    /// session counts against the holder's source limit and makes the next
    /// joiner fail with `NoPeer`.
    #[tokio::test]
    async fn i_join_closes_the_view_relay_session() {
        let (addr, stop, task) = start_proof_server().await;
        let root = tempfile::TempDir::new().expect("root");
        let mnt = root.path().join("mnt");
        std::fs::create_dir(&mnt).expect("mnt");
        let cluster = proof_cluster();
        let ring = Arc::new(KeyRing::derive(&[0x51; 32], &cluster).expect("ring"));
        let signing = proof_signing(0x47);
        let mut client = Client::new(proof_config(addr, &mnt, &signing, "close-a"))
            .with_cluster(cluster)
            .with_relay(true)
            .with_join_view(Arc::new(FixedView {
                manifest: Manifest::new(Seq::UNSEQUENCED, Vec::new()),
                blockmap: Blockmap::new(Seq::UNSEQUENCED, Vec::new(), Vec::new())
                    .expect("blockmap"),
            }));
        client.root = Some(Arc::new(RootFd::open_before_mount(&mnt).expect("root fd")));
        client.relay_ring = Some(Arc::clone(&ring));
        let parts = client
            .join_with_ring(Seq::UNSEQUENCED, 0, Some(&ring))
            .await
            .expect("join with a relay view");
        assert!(
            client
                .relay
                .as_ref()
                .expect("relay assembly")
                .link()
                .is_closed(),
            "cluster-wins must close the view relay session"
        );
        drop(parts);
        let _ = stop.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    /// F16: a client with the wrong PSK cannot even seal the envelope a
    /// member can open, so no answer arrives and the JOIN fails closed
    /// instead of entering STEADY.
    #[tokio::test]
    async fn i_join_proof_wrong_psk_is_rejected() {
        let (addr, stop, task) = start_proof_server().await;
        let root = tempfile::TempDir::new().expect("root");
        let cluster = proof_cluster();
        let master = proof_master(b"proof-test");
        let ring = Arc::new(KeyRing::derive(&[0x51; 32], &cluster).expect("ring"));

        let a_mount = root.path().join("a");
        std::fs::create_dir(&a_mount).expect("a dir");
        let signing_a = proof_signing(0x41);
        let mut a = Client::new(proof_config(addr, &a_mount, &signing_a, "proof-a"))
            .with_cluster(cluster)
            .with_join_auth(Arc::clone(&master), Arc::clone(&signing_a));
        let parts_a = a
            .join_with_ring(Seq::UNSEQUENCED, 0, Some(&ring))
            .await
            .expect("A joins the empty cluster");
        let auth_a = Arc::clone(a.join_auth.as_ref().expect("join auth"));
        let verifier =
            spawn_proof_verifier(parts_a, auth_a, Arc::clone(&ring), Arc::clone(a.keys()));

        let c_mount = root.path().join("c");
        std::fs::create_dir(&c_mount).expect("c dir");
        let signing_c = proof_signing(0x43);
        let wrong_master = proof_master(b"wrong-psk");
        let wrong_ring = Arc::new(KeyRing::derive(&[0x99; 32], &cluster).expect("wrong ring"));
        let mut c = Client::new(proof_config(addr, &c_mount, &signing_c, "proof-c"))
            .with_cluster(cluster)
            .with_join_auth(Arc::clone(&wrong_master), Arc::clone(&signing_c))
            .with_join_proof_timeout(Duration::from_millis(300));
        let error = c
            .join_with_ring(Seq::UNSEQUENCED, 0, Some(&wrong_ring))
            .await
            .expect_err("the wrong PSK must not join");
        match error {
            ClientError::Join(message) => {
                assert!(
                    message.contains("did not accept"),
                    "unexpected rejection reason: {message}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
        // Nothing was applied and no replayer exists: the client never
        // reached the join's local phase.
        assert!(c.replayer().is_none());

        verifier.abort();
        let _ = stop.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    /// The same cluster key but a proof that does not verify is refused
    /// explicitly with `JOIN_FAIL`, not by silence.
    #[tokio::test]
    async fn i_join_proof_invalid_proof_gets_join_fail() {
        let (addr, stop, task) = start_proof_server().await;
        let root = tempfile::TempDir::new().expect("root");
        let cluster = proof_cluster();
        let master = proof_master(b"proof-test");
        let ring = Arc::new(KeyRing::derive(&[0x51; 32], &cluster).expect("ring"));

        let a_mount = root.path().join("a");
        std::fs::create_dir(&a_mount).expect("a dir");
        let signing_a = proof_signing(0x41);
        let mut a = Client::new(proof_config(addr, &a_mount, &signing_a, "proof-a"))
            .with_cluster(cluster)
            .with_join_auth(Arc::clone(&master), Arc::clone(&signing_a));
        let parts_a = a
            .join_with_ring(Seq::UNSEQUENCED, 0, Some(&ring))
            .await
            .expect("A joins the empty cluster");
        let auth_a = Arc::clone(a.join_auth.as_ref().expect("join auth"));
        let verifier =
            spawn_proof_verifier(parts_a, auth_a, Arc::clone(&ring), Arc::clone(a.keys()));

        // The envelope opens (same ring), the proof inside does not.
        let d_mount = root.path().join("d");
        std::fs::create_dir(&d_mount).expect("d dir");
        let signing_d = proof_signing(0x44);
        let other_master = proof_master(b"other-master");
        let mut d = Client::new(proof_config(addr, &d_mount, &signing_d, "proof-d"))
            .with_cluster(cluster)
            .with_join_auth(Arc::clone(&other_master), Arc::clone(&signing_d))
            .with_join_proof_timeout(Duration::from_secs(2));
        let error = d
            .join_with_ring(Seq::UNSEQUENCED, 0, Some(&ring))
            .await
            .expect_err("an unverifiable proof must be refused");
        match error {
            ClientError::Join(message) => assert!(
                message.contains("rejected the JOIN proof"),
                "unexpected rejection reason: {message}"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(d.replayer().is_none());

        verifier.abort();
        let _ = stop.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    fn fuse_available() -> bool {
        if !cfg!(target_os = "linux")
            || !std::path::Path::new("/dev/fuse").exists()
            || !std::path::Path::new("/usr/bin/fusermount3").is_file()
        {
            if std::env::var("SYNCMOUNT_REQUIRE_FUSE").as_deref() == Ok("1") {
                panic!("FUSE required but /dev/fuse or fusermount3 is missing");
            }
            eprintln!("SKIP[FUSE] /dev/fuse or fusermount3 is missing");
            return false;
        }
        true
    }

    fn is_mounted_at(mountpoint: &Path) -> bool {
        let needle = mountpoint.to_string_lossy();
        std::fs::read_to_string("/proc/mounts")
            .map(|text| {
                text.lines().any(|line| {
                    line.split_whitespace()
                        .nth(1)
                        .map(|candidate| candidate == needle.as_ref())
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }

    async fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if predicate() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        predicate()
    }

    struct UnmountOnDrop(Vec<std::path::PathBuf>);

    impl Drop for UnmountOnDrop {
        fn drop(&mut self) {
            for mountpoint in &self.0 {
                let _ = std::process::Command::new("fusermount3")
                    .arg("-uz")
                    .arg(mountpoint)
                    .status();
            }
        }
    }

    /// End-to-end FUSE smoke: A writes through its mount, the uplink signs
    /// and seals the ORDERED, sends the payload on an OP_DATA relay, the
    /// server broadcasts, and B reads the bytes through its own FUSE mount.
    #[cfg(feature = "fuse")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn i_two_clients_fuse_write_read() {
        use std::fs;
        use std::sync::atomic::Ordering;

        use tokio::sync::oneshot;

        use crate::protocol::crypto::{ClusterId, KeyRing};
        use crate::server::{ServeConfig, Server};

        if !fuse_available() {
            return;
        }

        let server = Server::bind(ServeConfig::for_tests())
            .await
            .expect("server bind");
        let addr = server.local_addr().expect("server addr");
        let metrics = server.metrics();
        let (stop_tx, stop_rx) = oneshot::channel();
        let server_task = tokio::spawn(server.run_with_shutdown(async {
            let _ = stop_rx.await;
        }));

        let root = tempfile::TempDir::new().expect("root");
        let a_mnt = root.path().join("a");
        let b_mnt = root.path().join("b");
        let a_run = root.path().join("run-a");
        let b_run = root.path().join("run-b");
        let a_status = a_run.join("smoke-a").join("status.json");
        let b_status = b_run.join("smoke-b").join("status.json");
        for directory in [&a_mnt, &b_mnt, &a_run, &b_run] {
            fs::create_dir(directory).expect("test directory");
        }
        let _cleanup = UnmountOnDrop(vec![a_mnt.clone(), b_mnt.clone()]);

        let cluster = ClusterId::from_bytes([0x31; 16]);
        let id_a = Arc::new(crate::crypto::SigningKey::from_seed(&cluster, [0x41; 32]));
        let id_b = Arc::new(crate::crypto::SigningKey::from_seed(&cluster, [0x42; 32]));
        let master = Arc::new(
            crate::crypto::MasterKey::derive_from_password(b"smoke-master", &cluster)
                .expect("master key"),
        );
        let ring = Arc::new(KeyRing::derive(&[0x51; 32], &cluster).expect("key ring"));

        let config_a = Config {
            endpoint: Endpoint::parse(&format!("http://{addr}/")).expect("endpoint a"),
            mountpoint: a_mnt.clone(),
            client_id: id_a.client_id(),
            instance: InstanceId(0x61),
            mount_id: "smoke-a".to_owned(),
            tuning: Tuning::default(),
            password: PasswordSource::Tty,
            run_dir: a_run,
            allow_empty_view: false,
        };
        let config_b = Config {
            endpoint: Endpoint::parse(&format!("http://{addr}/")).expect("endpoint b"),
            mountpoint: b_mnt.clone(),
            client_id: id_b.client_id(),
            instance: InstanceId(0x62),
            mount_id: "smoke-b".to_owned(),
            tuning: Tuning::default(),
            password: PasswordSource::Tty,
            run_dir: b_run,
            allow_empty_view: false,
        };

        let mut a_task = tokio::spawn(
            Client::new(config_a)
                .with_cluster(cluster)
                .with_join_auth(Arc::clone(&master), Arc::clone(&id_a))
                .run_with_identity(Arc::clone(&ring), id_a),
        );
        let mut b_task = tokio::spawn(
            Client::new(config_b)
                .with_cluster(cluster)
                .with_join_auth(Arc::clone(&master), Arc::clone(&id_b))
                .run_with_identity(Arc::clone(&ring), id_b),
        );

        assert!(
            wait_until(Duration::from_secs(10), || {
                is_mounted_at(&a_mnt) && is_mounted_at(&b_mnt)
            })
            .await,
            "both FUSE mounts did not appear"
        );
        assert!(
            wait_until(Duration::from_secs(10), || {
                metrics.clients.load(Ordering::Relaxed) >= 2
            })
            .await,
            "both clients did not join"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert!(
            wait_until(Duration::from_secs(5), || a_status.is_file()).await,
            "status.json was not created at {}",
            a_status.display()
        );
        let initial: serde_json::Value =
            serde_json::from_slice(&fs::read(&a_status).expect("read initial status"))
                .expect("initial status json");
        assert_eq!(initial["mount_id"], "smoke-a");
        assert_eq!(initial["state"], "STEADY");
        assert!(initial["outbox"]["ops"].is_u64());
        assert!(initial["replay"]["pending"].is_u64());
        assert!(initial["replay"]["reorder"].is_u64());
        assert!(initial["replay"]["dedup"].is_u64());
        assert!(initial["counters"]["frames_in"].is_u64());
        assert!(initial["conntrace"].is_array());

        // Five files exercise five independent data relay sessions; the
        // uplink closes each with SYNC_END so the server's retry budget is
        // not consumed.
        for index in 0..5 {
            fs::write(a_mnt.join(format!("file-{index}.txt")), b"hello from A")
                .expect("A FUSE write");
        }

        // A's own echo must not re-materialise the write: the local bytes
        // stay exactly what the application wrote.
        assert_eq!(
            fs::read(a_mnt.join("file-0.txt")).expect("A reads own write"),
            b"hello from A"
        );

        for index in 0..5 {
            let name = format!("file-{index}.txt");
            let mut observed = None;
            for _ in 0..200 {
                if let Ok(bytes) = fs::read(b_mnt.join(&name)) {
                    if bytes == b"hello from A" {
                        observed = Some(bytes);
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            assert_eq!(
                observed.as_deref(),
                Some(b"hello from A".as_slice()),
                "B did not read A's FUSE write for {name}"
            );
        }
        assert!(
            wait_until(Duration::from_secs(5), || {
                fs::read(&a_status)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                    .is_some_and(|status| {
                        status["applied_seq"].as_u64().unwrap_or(0) > 0
                            && status["counters"]["ops_applied"].as_u64().unwrap_or(0) > 0
                            && status["conntrace"]
                                .as_array()
                                .is_some_and(|entries| !entries.is_empty())
                    })
            })
            .await,
            "status.json did not report applied operations and a connection trace"
        );
        println!(
            "W12 evidence: A FUSE write -> relay STREAM_DATA -> signed/sealed ORDERED -> B FUSE read (5 files); status.json state=STEADY applied_seq>0 conntrace non-empty"
        );

        // Nothing on the server ends an idle session: there is no T1/T5
        // timer. Sixteen quiet seconds prove that the mount survives the old
        // T1 (300 ms RTT fallback × 3) and T5 (15 s) windows.
        //
        // The client also sends no `PING` while its watermark is unchanged.
        // Let the status writer publish the post-write counters first, then
        // compare `frames_out` across the quiet window: any keepalive would
        // raise it.
        let frames_out = |path: &std::path::Path| -> u64 {
            fs::read(path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                .and_then(|status| status["counters"]["frames_out"].as_u64())
                .unwrap_or(0)
        };
        tokio::time::sleep(Duration::from_secs(6)).await;
        let quiet_frames = [frames_out(&a_status), frames_out(&b_status)];
        tokio::time::sleep(Duration::from_secs(16)).await;
        assert_eq!(
            frames_out(&a_status),
            quiet_frames[0],
            "A wrote uplink frames while idle"
        );
        assert_eq!(
            frames_out(&b_status),
            quiet_frames[1],
            "B wrote uplink frames while idle"
        );
        for (name, status, mountpoint) in [("A", &a_status, &a_mnt), ("B", &b_status, &b_mnt)] {
            let document: serde_json::Value =
                serde_json::from_slice(&fs::read(status).expect("read quiet status"))
                    .expect("quiet status json");
            assert_eq!(
                document["state"], "STEADY",
                "{name} left STEADY without a shutdown signal"
            );
            assert!(
                is_mounted_at(mountpoint),
                "{name} was unmounted without a shutdown signal"
            );
        }
        assert!(
            metrics.clients.load(Ordering::Relaxed) >= 2,
            "a client was detached while the mount stayed up"
        );
        println!(
            "heartbeat evidence: both clients STEADY and mounted 16 s after the last write (no T1/T5 timer); server clients={}",
            metrics.clients.load(Ordering::Relaxed)
        );

        let _ = stop_tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
        let a_code = tokio::time::timeout(Duration::from_secs(10), &mut a_task).await;
        let b_code = tokio::time::timeout(Duration::from_secs(10), &mut b_task).await;
        assert!(matches!(a_code, Ok(Ok(Ok(10)))), "A exit: {a_code:?}");
        assert!(matches!(b_code, Ok(Ok(Ok(10)))), "B exit: {b_code:?}");
    }

    /// Three clients, one data set. A writes seven files and stays STEADY;
    /// B joins and stays STEADY; C joins and stays STEADY. B's JOIN must close
    /// its view relay session before the writer changes hands. An open view
    /// session occupies the holder's single source slot, so C's `WELCOME`
    /// view token fails with `NoPeer` and C never reaches STEADY.
    #[cfg(feature = "fuse")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn i_three_clients_join_after_writes() {
        use std::fs;
        use std::sync::atomic::Ordering;

        use sha2::{Digest, Sha256};
        use tokio::sync::oneshot;

        use crate::protocol::crypto::{ClusterId, KeyRing};
        use crate::server::{ServeConfig, Server};

        if !fuse_available() {
            return;
        }

        struct Spec {
            config: Config,
            signing: Arc<crate::crypto::SigningKey>,
            mount: std::path::PathBuf,
            status: std::path::PathBuf,
        }

        let server = Server::bind(ServeConfig::for_tests())
            .await
            .expect("server bind");
        let addr = server.local_addr().expect("server addr");
        let metrics = server.metrics();
        let (stop_tx, stop_rx) = oneshot::channel();
        let server_task = tokio::spawn(server.run_with_shutdown(async {
            let _ = stop_rx.await;
        }));

        let root = tempfile::TempDir::new().expect("root");
        let cluster = ClusterId::from_bytes([0x32; 16]);
        let master = Arc::new(
            crate::crypto::MasterKey::derive_from_password(b"three-master", &cluster)
                .expect("master key"),
        );
        let ring = Arc::new(KeyRing::derive(&[0x52; 32], &cluster).expect("key ring"));

        let mut specs = Vec::new();
        for (index, seed) in [0x61u8, 0x62, 0x63].into_iter().enumerate() {
            let name = format!("three-{}", (b'a' + index as u8) as char);
            let mount = root.path().join(&name);
            let run = root.path().join(format!("run-{name}"));
            fs::create_dir(&mount).expect("mount dir");
            fs::create_dir(&run).expect("run dir");
            let signing = Arc::new(crate::crypto::SigningKey::from_seed(&cluster, [seed; 32]));
            let config = Config {
                endpoint: Endpoint::parse(&format!("http://{addr}/")).expect("endpoint"),
                mountpoint: mount.clone(),
                client_id: signing.client_id(),
                instance: InstanceId(u64::from(seed)),
                mount_id: name.clone(),
                tuning: Tuning::default(),
                password: PasswordSource::Tty,
                run_dir: run.clone(),
                allow_empty_view: false,
            };
            specs.push(Spec {
                config,
                signing,
                mount,
                status: run.join(&name).join("status.json"),
            });
        }
        let mounts: Vec<_> = specs.iter().map(|spec| spec.mount.clone()).collect();
        let _cleanup = UnmountOnDrop(mounts);
        let mut specs = specs.into_iter();
        let a = specs.next().expect("A spec");
        let b = specs.next().expect("B spec");
        let c = specs.next().expect("C spec");

        let status_of = |path: &std::path::Path| -> Option<serde_json::Value> {
            fs::read(path)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        };

        let mnt_a = a.mount.clone();
        let status_a = a.status.clone();
        let mut a_task = tokio::spawn(
            Client::new(a.config)
                .with_cluster(cluster)
                .with_join_auth(Arc::clone(&master), Arc::clone(&a.signing))
                .with_relay(true)
                .run_with_identity(Arc::clone(&ring), a.signing),
        );
        assert!(
            wait_until(Duration::from_secs(10), || {
                is_mounted_at(&mnt_a)
                    && status_of(&status_a).is_some_and(|status| status["state"] == "STEADY")
            })
            .await,
            "A did not reach STEADY"
        );

        for index in 0..7 {
            fs::write(
                mnt_a.join(format!("file-{index}.bin")),
                format!("payload-{index}"),
            )
            .expect("A FUSE write");
        }
        assert!(
            wait_until(Duration::from_secs(15), || {
                let seq = metrics.seq.load(Ordering::Relaxed);
                seq >= 7
                    && status_of(&status_a)
                        .is_some_and(|status| status["applied_seq"].as_u64() == Some(seq))
            })
            .await,
            "A's seven writes were not applied before B joined"
        );

        let mnt_b = b.mount.clone();
        let status_b = b.status.clone();
        let mut b_task = tokio::spawn(
            Client::new(b.config)
                .with_cluster(cluster)
                .with_join_auth(Arc::clone(&master), Arc::clone(&b.signing))
                .with_relay(true)
                .run_with_identity(Arc::clone(&ring), b.signing),
        );
        assert!(
            wait_until(Duration::from_secs(20), || {
                is_mounted_at(&mnt_b)
                    && status_of(&status_b).is_some_and(|status| status["state"] == "STEADY")
                    && metrics.clients.load(Ordering::Relaxed) == 2
            })
            .await,
            "B did not reach STEADY; C would then fail with NoPeer"
        );

        let mnt_c = c.mount.clone();
        let status_c = c.status.clone();
        let mut c_task = tokio::spawn(
            Client::new(c.config)
                .with_cluster(cluster)
                .with_join_auth(Arc::clone(&master), Arc::clone(&c.signing))
                .with_relay(true)
                .run_with_identity(Arc::clone(&ring), c.signing),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if is_mounted_at(&mnt_c)
                && status_of(&status_c).is_some_and(|status| status["state"] == "STEADY")
            {
                break;
            }
            if c_task.is_finished() {
                let outcome = (&mut c_task).await;
                panic!("C exited before STEADY (a NoPeer JOIN fails here): {outcome:?}");
            }
            assert!(Instant::now() < deadline, "C did not reach STEADY");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        assert!(
            wait_until(Duration::from_secs(5), || {
                serde_json::from_str::<serde_json::Value>(&metrics.healthz())
                    .ok()
                    .and_then(|health| health["clients"].as_u64())
                    == Some(3)
            })
            .await,
            "healthz did not report three clients: {}",
            metrics.healthz()
        );
        let healthz: serde_json::Value =
            serde_json::from_str(&metrics.healthz()).expect("healthz json");
        assert_eq!(healthz["clients"], 3, "healthz: {healthz}");

        for index in 0..7 {
            let name = format!("file-{index}.bin");
            let expected = Sha256::digest(fs::read(mnt_a.join(&name)).expect("A read"));
            let mut matched = false;
            for _ in 0..200 {
                if let Ok(bytes) = fs::read(mnt_c.join(&name)) {
                    if Sha256::digest(&bytes) == expected {
                        matched = true;
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            assert!(matched, "C's {name} SHA-256 differs from A's");
        }
        for (label, status) in [("A", &status_a), ("B", &status_b), ("C", &status_c)] {
            let document = status_of(status).expect("final status");
            assert_eq!(document["state"], "STEADY", "{label} left STEADY");
        }
        println!(
            "three-client evidence: A wrote 7 files, B and C joined into STEADY, \
             healthz clients=3, C's SHA-256 matches A's"
        );

        let _ = stop_tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
        let a_code = tokio::time::timeout(Duration::from_secs(10), &mut a_task).await;
        let b_code = tokio::time::timeout(Duration::from_secs(10), &mut b_task).await;
        let c_code = tokio::time::timeout(Duration::from_secs(10), &mut c_task).await;
        assert!(matches!(a_code, Ok(Ok(Ok(10)))), "A exit: {a_code:?}");
        assert!(matches!(b_code, Ok(Ok(Ok(10)))), "B exit: {b_code:?}");
        assert!(matches!(c_code, Ok(Ok(Ok(10)))), "C exit: {c_code:?}");
    }

    /// A third client may join while the second is still JOINING. The server
    /// forwards the new client's `JOIN_PROOF` to a peer that may itself be in
    /// `cluster_wins`; that peer's JoinReader must answer with `JOIN_ACCEPT`
    /// instead of only keeping the frame for the steady pump. Without the
    /// answer the joiner waits for a proof that never comes.
    #[cfg(feature = "fuse")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn i_concurrent_join_answers_proof() {
        use std::fs;
        use std::sync::atomic::Ordering;

        use sha2::{Digest, Sha256};
        use tokio::sync::oneshot;

        use crate::protocol::crypto::{ClusterId, KeyRing};
        use crate::server::{ServeConfig, Server};

        if !fuse_available() {
            return;
        }

        struct Spec {
            config: Config,
            signing: Arc<crate::crypto::SigningKey>,
            mount: std::path::PathBuf,
            status: std::path::PathBuf,
        }

        let server = Server::bind(ServeConfig::for_tests())
            .await
            .expect("server bind");
        let addr = server.local_addr().expect("server addr");
        let metrics = server.metrics();
        let (stop_tx, stop_rx) = oneshot::channel();
        let server_task = tokio::spawn(server.run_with_shutdown(async {
            let _ = stop_rx.await;
        }));

        let root = tempfile::TempDir::new().expect("root");
        let cluster = ClusterId::from_bytes([0x33; 16]);
        let master = Arc::new(
            crate::crypto::MasterKey::derive_from_password(b"concurrent-master", &cluster)
                .expect("master key"),
        );
        let ring = Arc::new(KeyRing::derive(&[0x53; 32], &cluster).expect("key ring"));

        let mut specs = Vec::new();
        for (index, seed) in [0x71u8, 0x72, 0x73].into_iter().enumerate() {
            let name = format!("concurrent-{}", (b'a' + index as u8) as char);
            let mount = root.path().join(&name);
            let run = root.path().join(format!("run-{name}"));
            fs::create_dir(&mount).expect("mount dir");
            fs::create_dir(&run).expect("run dir");
            let signing = Arc::new(crate::crypto::SigningKey::from_seed(&cluster, [seed; 32]));
            let config = Config {
                endpoint: Endpoint::parse(&format!("http://{addr}/")).expect("endpoint"),
                mountpoint: mount.clone(),
                client_id: signing.client_id(),
                instance: InstanceId(u64::from(seed)),
                mount_id: name.clone(),
                tuning: Tuning::default(),
                password: PasswordSource::Tty,
                run_dir: run.clone(),
                allow_empty_view: false,
            };
            specs.push(Spec {
                config,
                signing,
                mount,
                status: run.join(&name).join("status.json"),
            });
        }
        let mounts: Vec<_> = specs.iter().map(|spec| spec.mount.clone()).collect();
        let _cleanup = UnmountOnDrop(mounts);
        let mut specs = specs.into_iter();
        let a = specs.next().expect("A spec");
        let b = specs.next().expect("B spec");
        let c = specs.next().expect("C spec");

        let status_of = |path: &std::path::Path| -> Option<serde_json::Value> {
            fs::read(path)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        };

        let mnt_a = a.mount.clone();
        let status_a = a.status.clone();
        let mut a_task = tokio::spawn(
            Client::new(a.config)
                .with_cluster(cluster)
                .with_join_auth(Arc::clone(&master), Arc::clone(&a.signing))
                .with_relay(true)
                .run_with_identity(Arc::clone(&ring), a.signing),
        );
        assert!(
            wait_until(Duration::from_secs(10), || {
                is_mounted_at(&mnt_a)
                    && status_of(&status_a).is_some_and(|status| status["state"] == "STEADY")
            })
            .await,
            "A did not reach STEADY"
        );
        for index in 0..7 {
            fs::write(
                mnt_a.join(format!("file-{index}.bin")),
                format!("payload-{index}"),
            )
            .expect("A FUSE write");
        }
        assert!(
            wait_until(Duration::from_secs(15), || {
                let seq = metrics.seq.load(Ordering::Relaxed);
                seq >= 7
                    && status_of(&status_a)
                        .is_some_and(|status| status["applied_seq"].as_u64() == Some(seq))
            })
            .await,
            "A's seven writes were not applied before B and C joined"
        );

        // Start B first and C immediately after: C's JOIN_PROOF can reach B
        // while B is still installing its view.
        let mnt_b = b.mount.clone();
        let status_b = b.status.clone();
        let mut b_task = tokio::spawn(
            Client::new(b.config)
                .with_cluster(cluster)
                .with_join_auth(Arc::clone(&master), Arc::clone(&b.signing))
                .with_relay(true)
                .run_with_identity(Arc::clone(&ring), b.signing),
        );
        let mnt_c = c.mount.clone();
        let status_c = c.status.clone();
        let mut c_task = tokio::spawn(
            Client::new(c.config)
                .with_cluster(cluster)
                .with_join_auth(Arc::clone(&master), Arc::clone(&c.signing))
                .with_relay(true)
                .run_with_identity(Arc::clone(&ring), c.signing),
        );

        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let b_steady = is_mounted_at(&mnt_b)
                && status_of(&status_b).is_some_and(|status| status["state"] == "STEADY");
            let c_steady = is_mounted_at(&mnt_c)
                && status_of(&status_c).is_some_and(|status| status["state"] == "STEADY");
            if b_steady && c_steady && metrics.clients.load(Ordering::Relaxed) == 3 {
                break;
            }
            if b_task.is_finished() {
                let outcome = (&mut b_task).await;
                panic!(
                    "B exited before STEADY: {outcome:?}; status={:?} C={:?}",
                    status_of(&status_b),
                    status_of(&status_c)
                );
            }
            if c_task.is_finished() {
                let outcome = (&mut c_task).await;
                panic!(
                    "C exited before STEADY: {outcome:?}; status={:?} B={:?}",
                    status_of(&status_c),
                    status_of(&status_b)
                );
            }
            assert!(
                Instant::now() < deadline,
                "concurrent join did not reach STEADY: B={:?} C={:?} clients={}",
                status_of(&status_b),
                status_of(&status_c),
                metrics.clients.load(Ordering::Relaxed)
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        assert!(
            wait_until(Duration::from_secs(5), || {
                serde_json::from_str::<serde_json::Value>(&metrics.healthz())
                    .ok()
                    .and_then(|health| health["clients"].as_u64())
                    == Some(3)
            })
            .await,
            "healthz did not report three clients: {}",
            metrics.healthz()
        );
        for index in 0..7 {
            let name = format!("file-{index}.bin");
            let expected = Sha256::digest(fs::read(mnt_a.join(&name)).expect("A read"));
            let mut matched = false;
            for _ in 0..200 {
                if let Ok(bytes) = fs::read(mnt_c.join(&name)) {
                    if Sha256::digest(&bytes) == expected {
                        matched = true;
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            assert!(matched, "C's {name} SHA-256 differs from A's");
        }
        println!(
            "concurrent-join evidence: B and C joined while overlapping, \
             healthz clients=3, C's SHA-256 matches A's"
        );

        let _ = stop_tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
        let a_code = tokio::time::timeout(Duration::from_secs(10), &mut a_task).await;
        let b_code = tokio::time::timeout(Duration::from_secs(10), &mut b_task).await;
        let c_code = tokio::time::timeout(Duration::from_secs(10), &mut c_task).await;
        assert!(matches!(a_code, Ok(Ok(Ok(10)))), "A exit: {a_code:?}");
        assert!(matches!(b_code, Ok(Ok(Ok(10)))), "B exit: {b_code:?}");
        assert!(matches!(c_code, Ok(Ok(Ok(10)))), "C exit: {c_code:?}");
    }
}
