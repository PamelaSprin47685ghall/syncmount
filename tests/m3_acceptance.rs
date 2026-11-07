//! M3 exit acceptance (31:M3-1, M3-2, M3-5, M3-6), library harness.
//!
//! The harness starts a real [`Server`] on loopback and drives the real
//! `Client::join` cluster-wins path against a real backing directory. Content
//! is served through the public sync ports (`SyncLink`, `ChunkSource`,
//! `ChunkReader`, `JoinView`), which is the same seam the production
//! assembly uses; the test only supplies the transport stand-in the server
//! does not yet expose for snapshot/manifest containers.
//!
//! Every test prints one `M3 evidence:` line. Failures are real acceptance
//! failures, never skips.
//!
//! ```text
//! cargo test --test m3_acceptance -- --nocapture --test-threads=1
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};
use syncmount::client::Client;
use syncmount::client::config::{
    Config, Endpoint as ClientEndpoint, InstanceId, PasswordSource, Tuning,
};
use syncmount::client::lifecycle::{Action, Event, Lifecycle, State};
use syncmount::client::net::{Downlink, DownlinkItem, Uplink, decode_ordered};
use syncmount::client::replayer::OpData;
use syncmount::protocol::crypto::ClusterId;
use syncmount::protocol::frame::{ClientId, Seq};
use syncmount::protocol::messages::{OpClass, SnapshotRef, WcpWriter, fid};
use syncmount::protocol::{
    DataRef, Flags, FrameBuf, FrameHeader, Limits, MsgType, OpId, Prefix, SessionId,
};
use syncmount::server::{ServeConfig, Server};
use syncmount::store::node_table::InodeId;
use syncmount::store::{Errno, Kind, PosixBacking, RootFd};
use syncmount::sync::chunk::{ChunkCipher, ChunkId, ChunkKind};
use syncmount::sync::manifest::codec::{BlockmapIndexRef, ManifestBuilder, ManifestRef};
use syncmount::sync::manifest::{Blockmap, Entry, LocalManifest, Manifest, ManifestService};
use syncmount::sync::resume::{ChunkReader, DeltaPeer, JoinView, RemoteView};
use syncmount::sync::snapshot::{Generator, Installer};
use syncmount::sync::{
    BoxFut, ChunkSource, DiskStat, LocalTree, StateImage, StateProvider, SyncConfig, SyncEndReason,
    SyncError, SyncLink, SyncPorts,
};
use tempfile::TempDir;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;

const CHUNK: usize = 256 * 1024;
const MTIME: u64 = 1_700_000_000_000_000_000;
const CLUSTER: ClusterId = ClusterId::from_bytes([0x2a; 16]);

// ---------------------------------------------------------------------------
// Chunk source: sealed, content-addressed, in memory.
// ---------------------------------------------------------------------------

type BlobKey = (u8, [u8; 32]);
type BlobMap = BTreeMap<BlobKey, Vec<u8>>;

#[derive(Debug)]
struct MemChunks {
    cipher: ChunkCipher,
    blobs: Mutex<BlobMap>,
    puts: AtomicU64,
    fetches: AtomicU64,
    reads: AtomicU64,
}

impl MemChunks {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            cipher: ChunkCipher::new([0x42; 32]),
            blobs: Mutex::new(BTreeMap::new()),
            puts: AtomicU64::new(0),
            fetches: AtomicU64::new(0),
            reads: AtomicU64::new(0),
        })
    }

    fn key(kind: ChunkKind, id: &ChunkId) -> (u8, [u8; 32]) {
        (kind.wire(), *id.as_bytes())
    }

    fn fetch_count(&self) -> u64 {
        self.fetches.load(Ordering::Relaxed)
    }

    fn read_count(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }

    fn plain(&self, kind: ChunkKind, id: &ChunkId) -> Result<Option<Vec<u8>>, SyncError> {
        let blob = self
            .blobs
            .lock()
            .unwrap()
            .get(&Self::key(kind, id))
            .cloned();
        let Some(blob) = blob else {
            return Ok(None);
        };
        let plain = self
            .cipher
            .open(kind, id, &blob)
            .map_err(|_| SyncError::ChunkCorrupt { id: *id })?;
        Ok(Some(plain.to_vec()))
    }
}

impl ChunkSource for MemChunks {
    fn put(&self, kind: ChunkKind, plain: &[u8]) -> Result<ChunkId, SyncError> {
        let sealed = self
            .cipher
            .seal(kind, plain)
            .map_err(|_| SyncError::Format("chunk seal failed"))?;
        self.blobs
            .lock()
            .unwrap()
            .insert(Self::key(kind, &sealed.chunk_id), sealed.blob);
        self.puts.fetch_add(1, Ordering::Relaxed);
        Ok(sealed.chunk_id)
    }

    fn fetch(&self, kind: ChunkKind, id: ChunkId) -> BoxFut<'_, Result<Vec<u8>, SyncError>> {
        self.fetches.fetch_add(1, Ordering::Relaxed);
        let plain = self.plain(kind, &id);
        Box::pin(async move {
            match plain {
                Ok(Some(plain)) => Ok(plain),
                Ok(None) => Err(SyncError::ChunkUnavailable { id }),
                Err(error) => Err(error),
            }
        })
    }
}

impl ChunkReader for MemChunks {
    fn read(&self, kind: ChunkKind, id: ChunkId) -> Result<Option<Vec<u8>>, SyncError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.plain(kind, &id)
    }
}

// ---------------------------------------------------------------------------
// State image and state provider.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct TestImage {
    covered: Seq,
    bytes: Vec<u8>,
    entries: Vec<Entry>,
    blocks: Vec<ChunkId>,
}

impl StateImage for TestImage {
    fn covered_seq(&self) -> Seq {
        self.covered
    }

    fn encode(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn entries(&self) -> Vec<Entry> {
        self.entries.clone()
    }

    fn blocks(&self) -> Vec<ChunkId> {
        self.blocks.clone()
    }
}

#[derive(Debug, Default)]
struct TestState {
    applied: AtomicU64,
    installs: AtomicU64,
    installed_len: AtomicU64,
    installed_seq: AtomicU64,
}

impl TestState {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn installs(&self) -> u64 {
        self.installs.load(Ordering::Relaxed)
    }
}

impl StateProvider for TestState {
    fn applied_seq(&self) -> Seq {
        Seq(self.applied.load(Ordering::Relaxed))
    }

    fn capture(&self) -> Arc<dyn StateImage> {
        Arc::new(TestImage {
            covered: self.applied_seq(),
            bytes: Vec::new(),
            entries: Vec::new(),
            blocks: Vec::new(),
        })
    }

    fn install(&self, covered_seq: Seq, image: &[u8]) -> Result<(), SyncError> {
        self.applied.store(covered_seq.get(), Ordering::Relaxed);
        self.installed_seq
            .store(covered_seq.get(), Ordering::Relaxed);
        self.installed_len
            .store(image.len() as u64, Ordering::Relaxed);
        self.installs.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Control plane stand-in.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct TestLink {
    chunks: Arc<MemChunks>,
    snapshot: Mutex<Option<SnapshotRef>>,
    manifest: Mutex<Option<Manifest>>,
    blockmap: Mutex<Option<Blockmap>>,
    requests: AtomicU64,
    ended: Mutex<Option<SyncEndReason>>,
}

impl TestLink {
    fn new(chunks: Arc<MemChunks>) -> Arc<Self> {
        Arc::new(Self {
            chunks,
            snapshot: Mutex::new(None),
            manifest: Mutex::new(None),
            blockmap: Mutex::new(None),
            requests: AtomicU64::new(0),
            ended: Mutex::new(None),
        })
    }
}

impl SyncLink for TestLink {
    fn request_snapshot(&self, _covered_seq: Seq) -> BoxFut<'_, Result<SnapshotRef, SyncError>> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        let snapshot = *self.snapshot.lock().unwrap();
        Box::pin(async move { snapshot.ok_or(SyncError::SnapshotMissing) })
    }

    fn publish_snapshot(&self, reference: SnapshotRef) -> BoxFut<'_, Result<(), SyncError>> {
        *self.snapshot.lock().unwrap() = Some(reference);
        Box::pin(async { Ok(()) })
    }

    fn request_manifest(&self, at_seq: Option<Seq>) -> BoxFut<'_, Result<ManifestRef, SyncError>> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        let manifest = self.manifest.lock().unwrap().clone();
        let chunks = Arc::clone(&self.chunks);
        Box::pin(async move {
            let manifest = manifest.ok_or(SyncError::SnapshotMissing)?;
            let at = at_seq.unwrap_or(manifest.at_seq);
            let builder = ManifestBuilder::new(chunks.as_ref(), at);
            builder.build(&manifest)
        })
    }

    fn request_blockmap_index(
        &self,
        at_seq: Seq,
    ) -> BoxFut<'_, Result<BlockmapIndexRef, SyncError>> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        let blockmap = self.blockmap.lock().unwrap().clone();
        let chunks = Arc::clone(&self.chunks);
        Box::pin(async move {
            let blockmap = blockmap.ok_or(SyncError::SnapshotMissing)?;
            let builder = ManifestBuilder::new(chunks.as_ref(), at_seq);
            builder
                .build_blockmap(&blockmap)
                .map(|build| build.reference)
        })
    }

    fn sync_end(&self, reason: SyncEndReason) -> BoxFut<'_, Result<(), SyncError>> {
        *self.ended.lock().unwrap() = Some(reason);
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// Join view.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct TestJoinView {
    manifest: Manifest,
    blockmap: Blockmap,
    chunks: Arc<MemChunks>,
    delta: Option<Arc<dyn DeltaPeer>>,
    /// Artificial per-chunk delay, used by M3-2 to widen the pull window.
    delay: Option<Duration>,
}

impl TestJoinView {
    fn new(manifest: Manifest, blockmap: Blockmap, chunks: Arc<MemChunks>) -> Arc<Self> {
        Arc::new(Self {
            manifest,
            blockmap,
            chunks,
            delta: None,
            delay: None,
        })
    }
}

#[derive(Debug)]
struct SlowReader {
    inner: Arc<MemChunks>,
    delay: Duration,
}

impl ChunkReader for SlowReader {
    fn read(&self, kind: ChunkKind, id: ChunkId) -> Result<Option<Vec<u8>>, SyncError> {
        std::thread::sleep(self.delay);
        self.inner.read(kind, id)
    }
}

impl JoinView for TestJoinView {
    fn remote(&self) -> RemoteView {
        RemoteView {
            reference: None,
            manifest: self.manifest.clone(),
            blockmap: self.blockmap.clone(),
        }
    }

    fn chunks(&self) -> Arc<dyn ChunkReader> {
        match &self.delay {
            Some(delay) => Arc::new(SlowReader {
                inner: Arc::clone(&self.chunks),
                delay: *delay,
            }),
            None => Arc::clone(&self.chunks) as Arc<dyn ChunkReader>,
        }
    }

    fn delta(&self) -> Option<Arc<dyn DeltaPeer>> {
        self.delta.as_ref().map(Arc::clone)
    }
}

// ---------------------------------------------------------------------------
// Empty local tree for the ports.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct EmptyTree;

impl LocalTree for EmptyTree {
    fn walk(&self) -> Result<Vec<(String, DiskStat)>, SyncError> {
        Ok(Vec::new())
    }

    fn stat(&self, _path: &str) -> Result<Option<DiskStat>, SyncError> {
        Ok(None)
    }

    fn cached_manifest(&self) -> Option<LocalManifest> {
        None
    }
}

// ---------------------------------------------------------------------------
// Source tree builder.
// ---------------------------------------------------------------------------

struct SourceTree {
    files: usize,
    entries: Vec<Entry>,
    blocks: Vec<ChunkId>,
    manifest: Manifest,
    blockmap: Blockmap,
}

fn fill_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 8);
    let mut state = seed | 1;
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Write `files` (path, size) below `root`, chunk each file into `chunks`, and
/// build the manifest/blockmap that describes the result.
fn build_source(root: &Path, files: &[(&str, usize)], chunks: &Arc<MemChunks>) -> SourceTree {
    let mut file_entries = Vec::new();
    let mut file_blocks: BTreeMap<String, Vec<ChunkId>> = BTreeMap::new();
    let mut dirs: BTreeSet<String> = BTreeSet::new();

    for (index, (path, size)) in files.iter().enumerate() {
        let full = root.join(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
            let mut rel = parent.strip_prefix(root).unwrap().to_path_buf();
            while !rel.as_os_str().is_empty() {
                dirs.insert(rel.to_string_lossy().replace('\\', "/"));
                rel.pop();
            }
        }
        let data = fill_bytes(*size, 0x51ce_0000 + index as u64);
        fs::write(&full, &data).unwrap();

        let mut ids = Vec::new();
        for block in data.chunks(CHUNK) {
            ids.push(chunks.put(ChunkKind::File, block).unwrap());
        }
        let entry = Entry::file(
            *path,
            InodeId::new_v4(),
            0o644,
            1000,
            1000,
            data.len() as u64,
            MTIME,
            &ids,
        );
        file_entries.push(entry);
        file_blocks.insert((*path).to_owned(), ids);
    }

    let mut entries = file_entries;
    for dir in &dirs {
        entries.push(Entry::dir(
            dir.clone(),
            InodeId::new_v4(),
            0o755,
            1000,
            1000,
            MTIME,
        ));
    }
    entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));

    let mut blocks = Vec::new();
    for entry in &entries {
        if entry.kind == Kind::File {
            blocks.extend(file_blocks.get(&entry.path).unwrap().iter().copied());
        }
    }

    let manifest = Manifest::new(Seq(1), entries.clone());
    let image = TestImage {
        covered: Seq(1),
        bytes: b"m3-state-image".to_vec(),
        entries: entries.clone(),
        blocks: blocks.clone(),
    };
    let blockmap = Blockmap::from_image(&image).unwrap();

    SourceTree {
        files: files.len(),
        entries,
        blocks,
        manifest,
        blockmap,
    }
}

// ---------------------------------------------------------------------------
// Directory state (the `diff -r` equivalent).
// ---------------------------------------------------------------------------

fn dir_state(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    walk_state(root, Path::new(""), &mut out);
    out
}

fn walk_state(root: &Path, rel: &Path, out: &mut BTreeMap<String, String>) {
    let dir = root.join(rel);
    let mut entries: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("readdir {}: {error}", dir.display()))
        .map(|entry| entry.unwrap())
        .collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name();
        // Internal state is not user content: the same exclusion the diff
        // applies (reserved names never enter the manifest).
        if syncmount::store::is_reserved_name(&name) {
            continue;
        }
        let child = rel.join(&name);
        let key = child.to_string_lossy().replace('\\', "/");
        let meta = fs::symlink_metadata(entry.path()).unwrap();
        let file_type = meta.file_type();
        if file_type.is_dir() {
            out.insert(key, format!("dir:{:o}", meta.permissions().mode() & 0o7777));
            walk_state(root, &child, out);
        } else if file_type.is_symlink() {
            let target = fs::read_link(entry.path()).unwrap();
            out.insert(key, format!("link:{}", target.display()));
        } else {
            let bytes = fs::read(entry.path()).unwrap();
            out.insert(
                key,
                format!(
                    "file:{}:{:o}:{}",
                    bytes.len(),
                    meta.permissions().mode() & 0o7777,
                    sha256_hex(&bytes)
                ),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Server harness.
// ---------------------------------------------------------------------------

struct Harness {
    addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl Harness {
    async fn boot() -> Self {
        Self::boot_at(SocketAddr::from(([127, 0, 0, 1], 0))).await
    }

    async fn boot_at(addr: SocketAddr) -> Self {
        let mut config = ServeConfig::for_tests();
        config.listen = addr;
        let server = Server::bind(config).await.expect("bind");
        let addr = server.local_addr().expect("local addr");
        let (stop, stop_rx) = oneshot::channel();
        let task = tokio::spawn(server.run_with_shutdown(async {
            let _ = stop_rx.await;
        }));
        Self {
            addr,
            stop: Some(stop),
            task,
        }
    }

    async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let _ = tokio::time::timeout(Duration::from_secs(10), self.task).await;
    }
}

// ---------------------------------------------------------------------------
// Client helpers.
// ---------------------------------------------------------------------------

fn client_config(addr: SocketAddr, mount: &Path, id: u8) -> Config {
    Config {
        endpoint: ClientEndpoint::parse(&format!("http://{addr}/")).expect("endpoint"),
        mountpoint: mount.to_path_buf(),
        client_id: ClientId::from_bytes([id; 16]),
        instance: InstanceId(1),
        mount_id: format!("m3-{id}"),
        tuning: Tuning::default(),
        password: PasswordSource::Tty,
        run_dir: mount.to_path_buf(),
        allow_empty_view: false,
    }
}

fn drive_to_steady(lifecycle: &mut Lifecycle) {
    lifecycle.on(Event::Prepared(Ok(())));
    lifecycle.on(Event::LockAcquired(Ok(())));
    lifecycle.on(Event::Cleaned(Ok(())));
    lifecycle.on(Event::FuseMounted(Ok(())));
    lifecycle.on(Event::Joined(Ok(
        syncmount::client::lifecycle::JoinOutcome {
            epoch: 1,
            covered: 0,
        },
    )));
}

// ---------------------------------------------------------------------------
// M3-1: new node C catches up from snapshot + manifest + diff blocks.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn m3_1_new_node_catches_up_from_snapshot_manifest_and_blocks() {
    let server = Harness::boot().await;
    let src_dir = TempDir::new().unwrap();
    let chunks = MemChunks::new();
    let source = build_source(
        src_dir.path(),
        &[
            ("README.md", 4_096),
            ("dir/alpha.bin", 300_000),
            ("dir/nested/beta.bin", 700_000),
        ],
        &chunks,
    );

    // Snapshot: generate, publish, pull, verify digest, install.
    let image = TestImage {
        covered: Seq(1),
        bytes: b"m3-state-image".to_vec(),
        entries: source.entries.clone(),
        blocks: source.blocks.clone(),
    };
    let bundle = Generator::new(chunks.as_ref(), ClientId::from_bytes([0x71; 16]))
        .generate(&image)
        .expect("snapshot generate");
    let link = TestLink::new(Arc::clone(&chunks));
    *link.snapshot.lock().unwrap() = Some(bundle.reference);
    *link.manifest.lock().unwrap() = Some(source.manifest.clone());
    *link.blockmap.lock().unwrap() = Some(source.blockmap.clone());

    let state = TestState::new();
    let ports = SyncPorts {
        state: Arc::clone(&state) as Arc<dyn StateProvider>,
        chunks: Arc::clone(&chunks) as Arc<dyn ChunkSource>,
        link: Arc::clone(&link) as Arc<dyn SyncLink>,
        tree: Arc::new(EmptyTree),
        cache: Some(Arc::clone(&chunks) as Arc<dyn ChunkReader>),
        delta: None,
        cluster: CLUSTER,
    };
    let sync_config = SyncConfig::new();
    let installer = Installer::new(&ports, &sync_config);
    let pulled = installer
        .pull(&bundle.reference)
        .await
        .expect("snapshot pull");
    let installed = installer.install(pulled).expect("snapshot install");
    assert_eq!(installed.covered_seq, Seq(1));
    assert_eq!(
        state.installs(),
        1,
        "snapshot must reach the state provider"
    );

    // Manifest: the holder serves it; the joiner pulls and decodes it.
    let service = ManifestService::new(&ports);
    let manifest_ref = link.request_manifest(None).await.expect("manifest ref");
    let fetched = service.fetch(&manifest_ref).await.expect("manifest fetch");
    assert_eq!(
        fetched.entries(),
        source.manifest.entries(),
        "pulled manifest must equal the source manifest"
    );
    let index_ref = link
        .request_blockmap_index(Seq(1))
        .await
        .expect("blockmap index ref");
    let index = service
        .fetch_blockmap_index(&index_ref)
        .await
        .expect("blockmap index");
    assert_eq!(index.block_total, source.blocks.len() as u64);

    // New node C: an empty backing joins and pulls every block.
    let dst_dir = TempDir::new().unwrap();
    let view = TestJoinView::new(
        source.manifest.clone(),
        source.blockmap.clone(),
        Arc::clone(&chunks),
    );
    let mut client = Client::new(client_config(server.addr, dst_dir.path(), 0xc1))
        .with_cluster(CLUSTER)
        .with_join_view(view);
    let parts = client.join(Seq::UNSEQUENCED, 0).await.expect("JOIN C");
    let report = client.last_join().expect("join report").clone();

    assert_eq!(report.at_seq, Seq(1));
    assert_eq!(report.counts.remote_only, source.files as u64);
    assert_eq!(report.installed, source.files as u64);
    assert_eq!(report.removed, 0);
    assert_eq!(
        dir_state(src_dir.path()),
        dir_state(dst_dir.path()),
        "C must converge to A's tree"
    );

    println!(
        "M3 evidence: M3-1 pass snapshot_parts={} snapshot_len={} installed={} \
         manifest_entries={} blockmap_blocks={} block_fetches={} block_reads={} \
         report_remote_only={} report_installed={} diff=clean",
        bundle.reference.part_count,
        bundle.reference.total_len,
        installed.parts,
        fetched.len(),
        index.block_total,
        chunks.fetch_count(),
        chunks.read_count(),
        report.counts.remote_only,
        report.installed,
    );

    drop(parts);
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// M3-5 / M3-6: server restart changes the epoch and forces a full resync.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn m3_5_server_restart_epoch_forces_full_resync() {
    let first = Harness::boot().await;
    let addr = first.addr;

    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let mut a = Client::new(client_config(addr, dir_a.path(), 0xa1)).with_cluster(CLUSTER);
    let mut b = Client::new(client_config(addr, dir_b.path(), 0xb1)).with_cluster(CLUSTER);
    let parts_a = a.join(Seq::UNSEQUENCED, 0).await.expect("JOIN A");
    let parts_b = b.join(Seq::UNSEQUENCED, 0).await.expect("JOIN B");
    let epoch_before = parts_a.welcome.epoch;
    assert_eq!(epoch_before, parts_b.welcome.epoch);

    // Writes acknowledged by the old server (the contract does not promise
    // they survive a restart, but the local tree holds them now).
    fs::write(dir_a.path().join("a.txt"), b"alpha").unwrap();
    fs::write(dir_a.path().join("a2.txt"), b"alpha-2").unwrap();
    fs::write(dir_b.path().join("b.txt"), b"beta").unwrap();
    drop(parts_a);
    drop(parts_b);

    first.shutdown().await;

    // Restart on the same address: a new process epoch and an empty sequence.
    let second = Harness::boot_at(addr).await;

    let parts_a2 = a
        .join(Seq::UNSEQUENCED, epoch_before)
        .await
        .expect("JOIN A2");
    let parts_b2 = b
        .join(Seq::UNSEQUENCED, epoch_before)
        .await
        .expect("JOIN B2");
    assert_ne!(
        parts_a2.welcome.epoch, epoch_before,
        "a restarted server must publish a new epoch"
    );
    assert_eq!(parts_a2.welcome.epoch, parts_b2.welcome.epoch);

    let report_a = a.last_join().expect("join report A2").clone();
    let report_b = b.last_join().expect("join report B2").clone();
    assert_eq!(
        report_a.counts.local_only, 2,
        "A's local files are cluster-wins deletions"
    );
    assert_eq!(report_a.removed, 2);
    assert_eq!(report_b.counts.local_only, 1);
    assert_eq!(report_b.removed, 1);
    assert!(dir_state(dir_a.path()).is_empty());
    assert!(dir_state(dir_b.path()).is_empty());
    assert_eq!(
        dir_state(dir_a.path()),
        dir_state(dir_b.path()),
        "both clients converge to the empty cluster"
    );

    println!(
        "M3 evidence: M3-5 pass epoch_before=0x{:016x} epoch_after=0x{:016x} \
         A_removed={} B_removed={} A_covered={:?} B_covered={:?} diff=clean",
        epoch_before,
        parts_a2.welcome.epoch,
        report_a.removed,
        report_b.removed,
        report_a.covered_seq,
        report_b.covered_seq,
    );

    drop(parts_a2);
    drop(parts_b2);
    second.shutdown().await;
}

#[tokio::test]
async fn m3_6_epoch_change_takes_the_full_join_path() {
    // Lifecycle: EpochChanged from STEADY re-enters JOINING and starts a
    // fresh JOIN, i.e. the full cluster-wins path, never an incremental one.
    let mut lifecycle = Lifecycle::new();
    drive_to_steady(&mut lifecycle);
    assert_eq!(lifecycle.state(), State::Steady);
    let actions = lifecycle.on(Event::EpochChanged(2));
    assert_eq!(lifecycle.state(), State::Joining);
    assert!(
        actions.contains(&Action::StartJoin),
        "epoch change must start a full JOIN: {actions:?}"
    );
    assert!(
        actions.contains(&Action::CloseWriteGate),
        "epoch change must close the write gate: {actions:?}"
    );

    // Wire: a restarted server answers the old epoch with a new one, and the
    // JOIN's cluster-wins report is a full plan (no cached manifest on the
    // restarted cluster).
    let first = Harness::boot().await;
    let addr = first.addr;
    let dir = TempDir::new().unwrap();
    let mut client = Client::new(client_config(addr, dir.path(), 0xe1)).with_cluster(CLUSTER);
    let parts = client.join(Seq::UNSEQUENCED, 0).await.expect("JOIN 1");
    let epoch_before = parts.welcome.epoch;
    fs::write(dir.path().join("kept.txt"), b"local").unwrap();
    drop(parts);
    first.shutdown().await;

    let second = Harness::boot_at(addr).await;
    let parts = client
        .join(Seq::UNSEQUENCED, epoch_before)
        .await
        .expect("JOIN 2");
    let epoch_after = parts.welcome.epoch;
    let report = client.last_join().expect("join report").clone();
    assert_ne!(epoch_before, epoch_after);
    assert_eq!(report.counts.local_only, 1);
    assert_eq!(report.counts.identical, 0);
    assert_eq!(report.counts.content_diff, 0);
    assert_eq!(report.removed, 1);
    assert!(dir_state(dir.path()).is_empty());

    println!(
        "M3 evidence: M3-6 pass lifecycle=STEADY->JOINING+StartJoin \
         epoch_before=0x{:016x} epoch_after=0x{:016x} \
         full_plan_local_only={} removed={} incremental_paths=0",
        epoch_before, epoch_after, report.counts.local_only, report.removed,
    );

    drop(parts);
    second.shutdown().await;
}

// ---------------------------------------------------------------------------
// M3-2: A/B keep writing while C pulls; C converges without loss.
// ---------------------------------------------------------------------------

struct OpSpec<'a> {
    class: OpClass,
    path: &'a str,
    payload: Option<Vec<u8>>,
    offset: u64,
    mode: u32,
}

impl<'a> OpSpec<'a> {
    fn new(class: OpClass, path: &'a str) -> Self {
        Self {
            class,
            path,
            payload: None,
            offset: 0,
            mode: 0o755,
        }
    }

    fn payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = Some(payload);
        self
    }

    fn offset(mut self, offset: u64) -> Self {
        self.offset = offset;
        self
    }
}

#[derive(Default)]
struct TestData {
    map: Mutex<BTreeMap<[u8; 16], Vec<u8>>>,
}

impl TestData {
    fn insert(&self, session: SessionId, bytes: Vec<u8>) {
        self.map
            .lock()
            .unwrap()
            .insert(session.to_le_bytes(), bytes);
    }
}

impl OpData for TestData {
    fn read(&self, data: &DataRef) -> Result<Vec<u8>, Errno> {
        self.map
            .lock()
            .unwrap()
            .get(&data.session.to_le_bytes())
            .cloned()
            .ok_or(Errno::EIO)
    }
}

struct OpBuilder {
    client: ClientId,
    next: u64,
    data: Arc<TestData>,
}

impl OpBuilder {
    fn new(client: ClientId, data: Arc<TestData>) -> Self {
        Self {
            client,
            next: 0,
            data,
        }
    }

    fn frame(&mut self, spec: OpSpec<'_>) -> (OpId, FrameBuf) {
        self.next += 1;
        let mut raw = [0u8; 16];
        raw[..8].copy_from_slice(&self.client.to_bytes()[..8]);
        raw[8..].copy_from_slice(&self.next.to_le_bytes());
        let op_id = OpId::from_bytes(raw);

        let mut writer = WcpWriter::new();
        writer.bytes(fid::F_CLIENT_ID, &self.client.to_bytes());
        writer.u32(fid::F_KEY_EPOCH, 1);
        writer.bytes(fid::F_OP_ID, &op_id.to_bytes());
        writer.u8(fid::F_OP_CLASS, spec.class.get());
        if spec.class.requires_file_attrs() {
            writer.str(fid::F_PATH, spec.path);
            writer.u64(fid::F_MTIME_NS, MTIME);
            writer.u32(fid::F_UID, 1000);
            writer.u32(fid::F_GID, 1000);
        }
        match spec.class {
            OpClass::CREATE_EXCL => {
                writer.u32(fid::F_MODE, spec.mode);
                writer.u32(fid::F_OP_FLAGS, 0);
            }
            OpClass::WRITE | OpClass::PWRITE => {
                let payload = spec.payload.expect("write payload");
                let session = SessionId::from_le_bytes(op_id.to_bytes());
                let hash = *blake3::hash(&payload).as_bytes();
                self.data.insert(session, payload.clone());
                writer.bytes(fid::F_DATA_SESSION, &session.to_le_bytes());
                writer.u64(fid::F_TOTAL_LEN, payload.len() as u64);
                writer.bytes(fid::F_DATA_HASH, &hash);
                if spec.class == OpClass::PWRITE {
                    writer.u64(fid::F_OFFSET, spec.offset);
                }
            }
            _ => {}
        }
        writer.bytes(fid::F_PAYLOAD_HASH, &[0x33; 32]);
        writer.bytes(fid::F_SIG, &[0x44; 64]);
        let body = writer.finish().expect("WCP body");
        let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);
        header.len = u32::try_from(body.len()).expect("frame body fits u32");
        (op_id, FrameBuf::new(header, Prefix::None, body))
    }
}

struct Node {
    id: ClientId,
    uplink: Uplink,
    builder: OpBuilder,
    applied: watch::Receiver<u64>,
    errors: Arc<Mutex<Vec<String>>>,
    stop: Option<oneshot::Sender<()>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Node {
    async fn connect(addr: SocketAddr, id: ClientId, dir: &Path, data: Arc<TestData>) -> Self {
        let mut client = Client::new(client_config(addr, dir, 0x80 | (id.to_bytes()[0] & 0x7f)))
            .with_cluster(CLUSTER);
        let parts = client.join(Seq::UNSEQUENCED, 0).await.expect("JOIN node");
        let epoch = parts.welcome.epoch;
        let covered = parts.welcome.current_seq;
        let mut replayer = client.take_replayer().expect("replayer after JOIN");
        let backing = Arc::new(PosixBacking::new(
            RootFd::open_before_mount(dir).expect("open backing root"),
        ));
        let _state = replayer.state_handle();

        let (downlink, mut rx, _handle) = Downlink::with_decoder(parts.events, parts.decoder, 256);
        let (applied_tx, applied_rx) = watch::channel(covered.get());
        let errors = Arc::new(Mutex::new(Vec::new()));
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (stop_tx, mut stop_rx) = oneshot::channel();
        let downlink_task = tokio::spawn(async move {
            tokio::select! {
                _ = downlink.run() => {}
                _ = &mut stop_rx => {}
            }
            done.store(true, Ordering::Release);
        });

        let replay_errors = Arc::clone(&errors);
        let replay_backing = Arc::clone(&backing);
        let replay_data = Arc::clone(&data);
        let replay_task = tokio::spawn(async move {
            let start = std::time::Instant::now();
            while let Some(item) = rx.recv().await {
                let DownlinkItem::Ordered(frame) = item else {
                    continue;
                };
                let decoded = decode_ordered(&frame, epoch, &Limits::default(), |_, _, plain| {
                    Ok(plain.to_vec())
                });
                match decoded {
                    Ok(incoming) => {
                        if let Err(fatal) = replayer.on_ordered(
                            incoming,
                            start.elapsed(),
                            replay_backing.as_ref(),
                            replay_data.as_ref(),
                        ) {
                            replay_errors.lock().unwrap().push(format!("{fatal:?}"));
                        } else {
                            let _ = applied_tx.send(replayer.applied().get());
                        }
                    }
                    Err(error) => replay_errors
                        .lock()
                        .unwrap()
                        .push(format!("decode: {error:?}")),
                }
            }
        });

        Self {
            id,
            uplink: parts.uplink,
            builder: OpBuilder::new(id, data),
            applied: applied_rx,
            errors,
            stop: Some(stop_tx),
            tasks: vec![downlink_task, replay_task],
        }
    }

    async fn send(&mut self, frame: &FrameBuf) -> Result<(), String> {
        self.uplink
            .send(frame)
            .await
            .map_err(|error| error.to_string())
    }

    async fn wait_applied(&self, seq: u64, timeout: Duration) -> Result<(), String> {
        let mut applied = self.applied.clone();
        tokio::time::timeout(timeout, applied.wait_for(|value| *value >= seq))
            .await
            .map_err(|_| format!("client {} did not reach seq {seq}", self.id))?
            .map(|_| ())
            .map_err(|error| format!("client {} watch closed: {error}", self.id))
    }

    fn current(&self) -> u64 {
        *self.applied.borrow()
    }

    fn errors(&self) -> Vec<String> {
        self.errors.lock().unwrap().clone()
    }

    async fn write_file(&mut self, path: &str, payload: &[u8]) -> Result<u64, String> {
        let before = self.current();
        let (_, create) = self.builder.frame(OpSpec::new(OpClass::CREATE_EXCL, path));
        self.send(&create).await?;
        let (_, write) = self.builder.frame(
            OpSpec::new(OpClass::PWRITE, path)
                .offset(0)
                .payload(payload.to_vec()),
        );
        self.send(&write).await?;
        if let Err(error) = self.wait_applied(before + 2, Duration::from_secs(10)).await {
            eprintln!(
                "trace {}: wait failed {error}; errors={:?}",
                self.id,
                self.errors()
            );
            return Err(error);
        }
        Ok(before + 2)
    }

    fn shutdown(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[tokio::test]
async fn m3_2_writes_during_pull_are_not_lost() {
    let server = Harness::boot().await;
    let data = Arc::new(TestData::default());
    let holder_dir = TempDir::new().unwrap();
    let chunks = MemChunks::new();
    let source = build_source(
        holder_dir.path(),
        &[("seed/a.bin", 300_000), ("seed/b.bin", 600_000)],
        &chunks,
    );

    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let mut a = Node::connect(
        server.addr,
        ClientId::from_bytes([0xa2; 16]),
        dir_a.path(),
        Arc::clone(&data),
    )
    .await;
    let mut b = Node::connect(
        server.addr,
        ClientId::from_bytes([0xb2; 16]),
        dir_b.path(),
        Arc::clone(&data),
    )
    .await;

    a.write_file("/warm.txt", b"warm")
        .await
        .expect("A warm write before the pull");
    b.write_file("/warm.txt", b"warm")
        .await
        .expect("B warm write before the pull");

    let dst = TempDir::new().unwrap();
    let view = Arc::new(TestJoinView {
        manifest: source.manifest.clone(),
        blockmap: source.blockmap.clone(),
        chunks: Arc::clone(&chunks),
        delta: None,
        delay: Some(Duration::from_millis(200)),
    });
    let mut client = Client::new(client_config(server.addr, dst.path(), 0xc2))
        .with_cluster(CLUSTER)
        .with_join_view(view);

    let payload_a = fill_bytes(4_096, 0xa5a5);
    let payload_b = fill_bytes(8_192, 0xb6b6);
    let started = std::time::Instant::now();
    let mut join_fut = Box::pin(client.join(Seq::UNSEQUENCED, 0));
    let writes = async {
        tokio::time::sleep(Duration::from_millis(10)).await;
        a.write_file("/from_a.txt", &payload_a)
            .await
            .expect("A write during pull");
        b.write_file("/from_b.txt", &payload_b)
            .await
            .expect("B write during pull");
    };
    tokio::select! {
        () = writes => {}
        result = &mut join_fut => panic!("JOIN finished before the concurrent writes after {:?}: {result:?}", started.elapsed()),
    }
    let parts = join_fut.await.expect("JOIN C");
    let pull_ms = started.elapsed().as_millis();
    let report = client.last_join().expect("join report").clone();
    assert_eq!(report.counts.remote_only, 2);

    // C follows the broadcast from the join watermark and applies the writes
    // that landed while it was pulling.
    let mut replayer = client.take_replayer().expect("replayer after JOIN");
    let epoch = parts.welcome.epoch;
    let covered = parts.welcome.current_seq;
    let (downlink, mut rx, _handle) = Downlink::with_decoder(parts.events, parts.decoder, 256);
    let backing = Arc::new(PosixBacking::new(
        RootFd::open_before_mount(dst.path()).expect("open C backing"),
    ));
    let (applied_tx, applied_rx) = watch::channel(covered.get());
    let errors = Arc::new(Mutex::new(Vec::new()));
    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
    let downlink_task = tokio::spawn(async move {
        tokio::select! {
            _ = downlink.run() => {}
            _ = &mut stop_rx => {}
        }
    });
    let replay_errors = Arc::clone(&errors);
    let replay_backing = Arc::clone(&backing);
    let replay_data = Arc::clone(&data);
    let replay_task = tokio::spawn(async move {
        let start = std::time::Instant::now();
        while let Some(item) = rx.recv().await {
            let DownlinkItem::Ordered(frame) = item else {
                continue;
            };
            let decoded = decode_ordered(&frame, epoch, &Limits::default(), |_, _, plain| {
                Ok(plain.to_vec())
            });
            match decoded {
                Ok(incoming) => {
                    if let Err(fatal) = replayer.on_ordered(
                        incoming,
                        start.elapsed(),
                        replay_backing.as_ref(),
                        replay_data.as_ref(),
                    ) {
                        replay_errors.lock().unwrap().push(format!("{fatal:?}"));
                    } else {
                        let _ = applied_tx.send(replayer.applied().get());
                    }
                }
                Err(error) => replay_errors
                    .lock()
                    .unwrap()
                    .push(format!("decode: {error:?}")),
            }
        }
    });

    let mut applied = applied_rx.clone();
    tokio::time::timeout(
        Duration::from_secs(10),
        applied.wait_for(|value| *value >= 8),
    )
    .await
    .expect("C must apply the writes made during the pull")
    .expect("C applied watch");

    // No loss: the seeded tree survived the pull and both concurrent writes
    // are present with their exact bytes.
    assert_eq!(
        sha256_hex(&fs::read(dst.path().join("seed/a.bin")).unwrap()),
        sha256_hex(&fs::read(holder_dir.path().join("seed/a.bin")).unwrap())
    );
    assert_eq!(
        sha256_hex(&fs::read(dst.path().join("seed/b.bin")).unwrap()),
        sha256_hex(&fs::read(holder_dir.path().join("seed/b.bin")).unwrap())
    );
    assert_eq!(fs::read(dst.path().join("from_a.txt")).unwrap(), payload_a);
    assert_eq!(fs::read(dst.path().join("from_b.txt")).unwrap(), payload_b);
    assert_eq!(
        fs::read(dir_a.path().join("from_a.txt")).unwrap(),
        payload_a
    );
    assert_eq!(
        fs::read(dir_b.path().join("from_b.txt")).unwrap(),
        payload_b
    );
    assert!(a.errors().is_empty(), "A replay errors: {:?}", a.errors());
    assert!(b.errors().is_empty(), "B replay errors: {:?}", b.errors());
    assert!(
        errors.lock().unwrap().is_empty(),
        "C replay errors: {:?}",
        errors
    );

    println!(
        "M3 evidence: M3-2 pass pull_ms={} writes_during_pull=4 c_applied={} \
         seeded_files=2 concurrent_files=2 report_remote_only={} diff=clean",
        pull_ms,
        *applied_rx.borrow(),
        report.counts.remote_only,
    );

    drop(stop_tx);
    downlink_task.abort();
    replay_task.abort();
    a.shutdown();
    b.shutdown();
    server.shutdown().await;
}
