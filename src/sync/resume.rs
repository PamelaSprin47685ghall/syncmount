//! Join journal, derived resume ledger, and the cluster-wins applier.
//!
//! Owner: W17 (E7). See 43 §5.5, §6.3–§6.4, §8.3 (I5, I6) and 53 W17.
//!
//! # Three different kinds of memory
//!
//! | value | authority | lost means |
//! |---|---|---|
//! | [`SyncState`] | none — a phase journal | re-run the phase, never wrong data |
//! | [`Resume`] | none — recomputed from manifest + blockmap + cache | recompute it |
//! | [`Ledger`] | none — a [`Resume`] plus local marks | recompute it |
//!
//! The only authority is content: a chunk is "received" exactly when the
//! cache holds `BLAKE3(plaintext) == chunk_id` (43 I6). Everything in this
//! module is an accelerator, so every operation has a recompute path.
//!
//! # Cluster wins
//!
//! [`ClusterWins`] executes a [`DiffPlan`] against a real backing root:
//!
//! 1. directories, deepest-first removals and attribute-only items go into an
//!    [`ApplyPlan`];
//! 2. `RemoteOnly`/`TypeReplace` files are staged chunk by chunk from the
//!    content cache;
//! 3. `ContentDiff` files run the W15 three-step rsync
//!    (`signature → peer delta → patch`) per 16 MiB segment;
//! 4. every staged file is re-hashed into 256 KiB blocks and its `file_root`
//!    is compared with the manifest before one `renameat` publishes it;
//! 5. symlinks are created after the file apply, replacing the old item
//!    through `trash/`.
//!
//! There is no whole-tree swap and no global commit point (C-31). A failure
//! leaves each path at either its old or its new version.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustix::fs::{Mode, OFlags};

use crate::protocol::frame::{Seq, SessionId};
use crate::store::backing::RootFd;
use crate::store::chunk_store::{CHUNK_BYTES, ChunkId, ChunkKind, ChunkStore};
use crate::store::{AttrDelta, Errno, Kind, RenameFlags, Timespec};
use crate::sync::chunk::VerifiedChunkStore;
use crate::sync::manifest::{Blockmap, Entry, Manifest, file_root};
use crate::sync::rsync::{DeltaEngine, SEGMENT_BYTES};
use crate::sync::staging::{
    ApplyPlan, ApplyReport, StagedFile, StagingBuild, TRASH_DIR, apply, ensure_layout,
};
use crate::sync::state::{Machine, SyncError, SyncEvent, SyncPhase};
use crate::sync::{DiffKind, DiffPlan, DiskStat, PlanItem, wire};

/// The journal path below the backing root (43 §6.1).
pub const JOURNAL_FILE: &str = ".syncmount-staging/join.journal";
/// Temporary sibling used for the atomic replace.
pub const JOURNAL_TMP: &str = ".syncmount-staging/join.journal.tmp";
/// Journal magic.
pub const JOURNAL_MAGIC: [u8; 4] = *b"SMJN";
/// Journal format version.
pub const JOURNAL_VERSION: u8 = 1;

/// The journal is small and fixed-width: magic, version, phase, resume phase,
/// session, epoch, covered seq, at seq, manifest root, staging root, digest.
const JOURNAL_BODY_LEN: usize = 4 + 1 + 1 + 1 + SessionId::LEN + 8 + 8 + 8 + 32 + 32;
const JOURNAL_LEN: usize = JOURNAL_BODY_LEN + 32;

// ---------------------------------------------------------------------------
// Phase journal
// ---------------------------------------------------------------------------

/// The durable phase record of one join.
///
/// It wraps the pure [`Machine`] (W14) and adds the values a resumed join
/// needs to decide what it may skip. Nothing here is authoritative: a
/// corrupt or missing journal costs one re-fetch, never a wrong byte.
#[derive(Clone, Debug)]
pub struct SyncState {
    machine: Machine,
    session_id: SessionId,
    epoch: u64,
    covered_seq: Seq,
    at_seq: Seq,
    manifest_root: [u8; 32],
    staging_root: [u8; 32],
}

impl SyncState {
    /// A journal at `Idle` with no session.
    pub const fn new() -> Self {
        Self {
            machine: Machine::new(),
            session_id: SessionId::ZERO,
            epoch: 0,
            covered_seq: Seq::UNSEQUENCED,
            at_seq: Seq::UNSEQUENCED,
            manifest_root: [0u8; 32],
            staging_root: [0u8; 32],
        }
    }

    /// Current phase.
    pub const fn phase(&self) -> SyncPhase {
        self.machine.phase()
    }

    /// The phase a `Resume` would return to.
    pub const fn resume_target(&self) -> Option<SyncPhase> {
        self.machine.resume_target()
    }

    /// Session identity.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Epoch the join runs under.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Sequence covered by the installed snapshot, when one was installed.
    pub const fn covered_seq(&self) -> Seq {
        self.covered_seq
    }

    /// Sequence the remote manifest was generated at.
    pub const fn at_seq(&self) -> Seq {
        self.at_seq
    }

    /// Manifest root recorded for diagnostics.
    pub const fn manifest_root(&self) -> [u8; 32] {
        self.manifest_root
    }

    /// Staging root recorded for diagnostics.
    pub const fn staging_root(&self) -> [u8; 32] {
        self.staging_root
    }

    /// Record the session the join belongs to.
    pub fn set_session(&mut self, session_id: SessionId, epoch: u64) {
        self.session_id = session_id;
        self.epoch = epoch;
    }

    /// Record the installed snapshot's watermark.
    pub fn note_snapshot(&mut self, covered_seq: Seq) {
        self.covered_seq = covered_seq;
    }

    /// Record the manifest sequence and root.
    pub fn note_manifest(&mut self, at_seq: Seq, manifest_root: [u8; 32]) {
        self.at_seq = at_seq;
        self.manifest_root = manifest_root;
    }

    /// Record the staging identity.
    pub fn note_staging(&mut self, staging_root: [u8; 32]) {
        self.staging_root = staging_root;
    }

    /// Advance the phase machine.
    ///
    /// # Errors
    ///
    /// [`SyncError::IllegalTransition`] for a pair the table does not allow.
    pub fn advance(&mut self, event: SyncEvent) -> Result<SyncPhase, SyncError> {
        self.machine.apply(event)
    }

    /// True when `phase` lies strictly before the current one and the journal
    /// is not aborted. `Failing` is never "completed": it is a detour, not a
    /// milestone.
    pub fn completed(&self, phase: SyncPhase) -> bool {
        if phase == SyncPhase::Failing || self.phase() == SyncPhase::Aborted {
            return false;
        }
        let current = match self.phase() {
            SyncPhase::Failing => self.resume_target().unwrap_or(SyncPhase::Idle),
            other => other,
        };
        current > phase
    }

    /// Encode the journal body plus its digest.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(JOURNAL_LEN);
        wire::put_magic(&mut out, JOURNAL_MAGIC);
        wire::put_u8(&mut out, JOURNAL_VERSION);
        wire::put_u8(&mut out, phase_code(self.phase()));
        wire::put_u8(
            &mut out,
            self.resume_target().map_or(PHASE_NONE, phase_code),
        );
        out.extend_from_slice(&self.session_id.to_le_bytes());
        wire::put_u64(&mut out, self.epoch);
        wire::put_u64(&mut out, self.covered_seq.get());
        wire::put_u64(&mut out, self.at_seq.get());
        out.extend_from_slice(&self.manifest_root);
        out.extend_from_slice(&self.staging_root);
        debug_assert_eq!(out.len(), JOURNAL_BODY_LEN);
        let digest = blake3::hash(&out);
        out.extend_from_slice(digest.as_bytes());
        out
    }

    /// Decode and verify a journal.
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] for a bad magic, version, phase code, length or
    /// digest.
    pub fn decode(bytes: &[u8]) -> Result<Self, SyncError> {
        if bytes.len() != JOURNAL_LEN {
            return Err(SyncError::Format("journal length mismatch"));
        }
        let (body, digest) = bytes.split_at(JOURNAL_BODY_LEN);
        if blake3::hash(body).as_bytes() != digest {
            return Err(SyncError::Format("journal digest mismatch"));
        }
        let mut reader = wire::Reader::new(body);
        reader.magic(JOURNAL_MAGIC)?;
        let version = reader.u8()?;
        if version != JOURNAL_VERSION {
            return Err(SyncError::Format("unsupported journal version"));
        }
        let phase = phase_from(reader.u8()?).ok_or(SyncError::Format("unknown journal phase"))?;
        let resume_code = reader.u8()?;
        let resume = if resume_code == PHASE_NONE {
            None
        } else {
            Some(phase_from(resume_code).ok_or(SyncError::Format("unknown resume phase"))?)
        };
        let session_id = SessionId::new(u128::from_le_bytes(reader.array16()?));
        let epoch = reader.u64()?;
        let covered_seq = Seq(reader.u64()?);
        let at_seq = Seq(reader.u64()?);
        let manifest_root = reader.array32()?;
        let staging_root = reader.array32()?;
        reader.finish()?;

        let mut machine = Machine::new();
        if phase == SyncPhase::Failing {
            // Reconstruct "failing with a remembered target" by advancing to
            // the target first, then retrying.
            let target = resume.ok_or(SyncError::Format("failing journal without target"))?;
            replay_to(&mut machine, target)?;
            machine.apply(SyncEvent::Retry)?;
        } else {
            replay_to(&mut machine, phase)?;
        }
        Ok(Self {
            machine,
            session_id,
            epoch,
            covered_seq,
            at_seq,
            manifest_root,
            staging_root,
        })
    }

    /// Load the journal; any error means "no usable journal" (43 §6.4).
    pub fn load(root: &RootFd) -> Option<Self> {
        let bytes = read_file(root, Path::new(JOURNAL_FILE)).ok()??;
        Self::decode(&bytes).ok()
    }

    /// Replace the journal atomically.
    ///
    /// # Errors
    ///
    /// [`SyncError::Io`] when the staging layout cannot be created or the
    /// temporary file cannot be renamed.
    pub fn save(&self, root: &RootFd) -> Result<(), SyncError> {
        ensure_layout(root).map_err(staging_error)?;
        write_file(root, Path::new(JOURNAL_TMP), &self.encode())?;
        root.rename_at(
            Path::new(JOURNAL_TMP),
            Path::new(JOURNAL_FILE),
            RenameFlags::NONE,
        )?;
        Ok(())
    }

    /// Remove the journal; `ENOENT` is success.
    ///
    /// # Errors
    ///
    /// Any other `unlinkat` failure.
    pub fn discard(root: &RootFd) -> Result<(), SyncError> {
        match root.unlink_at(Path::new(JOURNAL_FILE)) {
            Ok(()) => Ok(()),
            Err(err) if err == Errno::ENOENT => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}

impl Default for SyncState {
    fn default() -> Self {
        Self::new()
    }
}

const PHASE_NONE: u8 = u8::MAX;

fn phase_code(phase: SyncPhase) -> u8 {
    match SyncPhase::ALL.iter().position(|known| *known == phase) {
        Some(index) => index as u8,
        None => PHASE_NONE,
    }
}

fn phase_from(code: u8) -> Option<SyncPhase> {
    SyncPhase::ALL.get(usize::from(code)).copied()
}

/// Drive a fresh machine along the happy path up to `target`.
///
/// `Online` and `Aborted` are reached by their last event; `Failing` is
/// handled by the caller because it needs a resume target.
fn replay_to(machine: &mut Machine, target: SyncPhase) -> Result<(), SyncError> {
    use SyncEvent as E;
    use SyncPhase as P;
    let path: &[(E, P)] = &[
        (E::Welcome, P::Handshake),
        (E::SnapshotRef, P::SnapshotSelect),
        (E::SnapshotSelected, P::SnapshotPull),
        (E::PartsComplete, P::SnapshotInstall),
        (E::Installed, P::ManifestFetch),
        (E::ManifestDone, P::DiffPlan),
        (E::Planned, P::RsyncRun),
        (E::AllFilesDone, P::StagingBuild),
        (E::Staged, P::Durability),
        (E::Durable, P::Apply),
        (E::Applied, P::Commit),
        (E::Committed, P::Online),
    ];
    if target == P::Idle {
        return Ok(());
    }
    if target == P::Aborted {
        machine.apply(E::Abort)?;
        return Ok(());
    }
    if target == P::Failing {
        return Err(SyncError::Format("failing phase needs a resume target"));
    }
    for (event, _phase) in path {
        let reached = machine.apply(*event)?;
        if reached == target {
            return Ok(());
        }
    }
    Err(SyncError::Format("journal phase is unreachable"))
}

// ---------------------------------------------------------------------------
// Derived resume
// ---------------------------------------------------------------------------

/// What the cache can answer about a chunk.
pub trait ChunkPresence: Send + Sync {
    /// True when `(kind, id)` is cached.
    fn has(&self, kind: ChunkKind, id: ChunkId) -> bool;
}

impl ChunkPresence for ChunkStore {
    fn has(&self, kind: ChunkKind, id: ChunkId) -> bool {
        ChunkStore::has(self, kind, &id)
    }
}

impl ChunkPresence for VerifiedChunkStore {
    fn has(&self, kind: ChunkKind, id: ChunkId) -> bool {
        VerifiedChunkStore::has(self, kind, &id)
    }
}

/// Per-file resume counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileResume {
    /// Blocks that are not in the cache.
    pub needed: u32,
    /// Blocks that are in the cache.
    pub received: u32,
    /// Bytes of the missing blocks.
    pub needed_bytes: u64,
    /// Bytes of the cached blocks.
    pub received_bytes: u64,
}

/// The transfer set derived from manifest, blockmap and cache.
///
/// `needed` means "must still be fetched"; `received` means "already in the
/// cache". Both are recomputed, never persisted as truth.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Resume {
    at_seq: Seq,
    needed: BTreeSet<ChunkId>,
    received: BTreeSet<ChunkId>,
    files: BTreeMap<u32, FileResume>,
    needed_bytes: u64,
    received_bytes: u64,
}

impl Resume {
    /// Derive the set for every regular file in `manifest`.
    ///
    /// # Errors
    ///
    /// [`SyncError::Format`] when the blockmap is sparse or disagrees with the
    /// manifest; a sparse map cannot answer "is this block cached" for the
    /// files it does not cover.
    pub fn derive(
        manifest: &Manifest,
        blockmap: &Blockmap,
        cache: &dyn ChunkPresence,
    ) -> Result<Self, SyncError> {
        let mut resume = Self {
            at_seq: manifest.at_seq,
            ..Self::default()
        };
        for (index, entry) in manifest.entries().iter().enumerate() {
            if entry.kind != Kind::File || entry.block_count == 0 {
                continue;
            }
            let file_index = u32::try_from(index)
                .map_err(|_| SyncError::Format("manifest has too many entries"))?;
            let blocks = blockmap
                .file_blocks(file_index)
                .ok_or(SyncError::Format("blockmap is sparse for resume"))?;
            if blocks.len() as u32 != entry.block_count {
                return Err(SyncError::Format("blockmap disagrees with manifest"));
            }
            let mut file = FileResume::default();
            for (block, id) in blocks.into_iter().enumerate() {
                let bytes = block_bytes(entry, block as u32);
                if cache.has(ChunkKind::File, id) {
                    resume.received.insert(id);
                    resume.received_bytes = resume.received_bytes.saturating_add(bytes);
                    file.received += 1;
                    file.received_bytes = file.received_bytes.saturating_add(bytes);
                } else {
                    resume.needed.insert(id);
                    resume.needed_bytes = resume.needed_bytes.saturating_add(bytes);
                    file.needed += 1;
                    file.needed_bytes = file.needed_bytes.saturating_add(bytes);
                }
            }
            resume.files.insert(file_index, file);
        }
        Ok(resume)
    }

    /// Sequence the derivation was made for.
    pub const fn at_seq(&self) -> Seq {
        self.at_seq
    }

    /// Blocks that still need a fetch.
    pub fn needed(&self) -> impl Iterator<Item = ChunkId> + '_ {
        self.needed.iter().copied()
    }

    /// Blocks already in the cache.
    pub fn received(&self) -> impl Iterator<Item = ChunkId> + '_ {
        self.received.iter().copied()
    }

    /// Missing block count.
    pub fn needed_count(&self) -> usize {
        self.needed.len()
    }

    /// Cached block count.
    pub fn received_count(&self) -> usize {
        self.received.len()
    }

    /// Missing bytes.
    pub const fn needed_bytes(&self) -> u64 {
        self.needed_bytes
    }

    /// Cached bytes.
    pub const fn received_bytes(&self) -> u64 {
        self.received_bytes
    }

    /// True when every block is cached.
    pub fn is_complete(&self) -> bool {
        self.needed.is_empty()
    }

    /// Per-file counters.
    pub fn files(&self) -> &BTreeMap<u32, FileResume> {
        &self.files
    }

    /// Per-file counters for one manifest index.
    pub fn file(&self, index: u32) -> Option<&FileResume> {
        self.files.get(&index)
    }
}

/// The byte length of one block of `entry`.
fn block_bytes(entry: &Entry, block: u32) -> u64 {
    let start = u64::from(block).saturating_mul(CHUNK_BYTES as u64);
    entry.size.saturating_sub(start).min(CHUNK_BYTES as u64)
}

/// A [`Resume`] plus non-authoritative local marks.
///
/// Marks only shrink [`Ledger::pending`]; they never change
/// [`Ledger::is_complete`], which stays the derived truth. [`Ledger::refresh`]
/// throws every mark away, so a wrong mark can only delay a fetch by one
/// refresh, never hide a missing block.
#[derive(Clone, Debug)]
pub struct Ledger {
    derived: Resume,
    marked: BTreeSet<ChunkId>,
}

impl Ledger {
    /// Wrap a derived set.
    pub fn new(derived: Resume) -> Self {
        Self {
            derived,
            marked: BTreeSet::new(),
        }
    }

    /// Derive a fresh ledger.
    ///
    /// # Errors
    ///
    /// Same as [`Resume::derive`].
    pub fn derive(
        manifest: &Manifest,
        blockmap: &Blockmap,
        cache: &dyn ChunkPresence,
    ) -> Result<Self, SyncError> {
        Ok(Self::new(Resume::derive(manifest, blockmap, cache)?))
    }

    /// The derived set.
    pub const fn resume(&self) -> &Resume {
        &self.derived
    }

    /// Mark a block as received locally.
    ///
    /// Returns `false` when the block is not in the derived need set or was
    /// already marked. The mark is a hint for progress display only.
    pub fn mark_received(&mut self, id: ChunkId) -> bool {
        self.derived.needed.contains(&id) && self.marked.insert(id)
    }

    /// Blocks still missing after applying the marks.
    pub fn pending(&self) -> impl Iterator<Item = ChunkId> + '_ {
        self.derived.needed.difference(&self.marked).copied()
    }

    /// Missing block count after applying the marks.
    pub fn pending_count(&self) -> usize {
        self.derived.needed.len().saturating_sub(self.marked.len())
    }

    /// Authoritative completion: the derived set, not the marks.
    pub fn is_complete(&self) -> bool {
        self.derived.is_complete()
    }

    /// Recompute from the authority and drop every mark.
    ///
    /// # Errors
    ///
    /// Same as [`Resume::derive`].
    pub fn refresh(
        &mut self,
        manifest: &Manifest,
        blockmap: &Blockmap,
        cache: &dyn ChunkPresence,
    ) -> Result<(), SyncError> {
        self.derived = Resume::derive(manifest, blockmap, cache)?;
        self.marked.clear();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Cluster-wins apply
// ---------------------------------------------------------------------------

/// A source of verified plaintext chunks.
///
/// The fetch stage fills the cache; the apply stage only reads it. Keeping the
/// apply synchronous makes it a single `spawn_blocking` unit on the client
/// side and keeps the port testable without a socket.
pub trait ChunkReader: Send + Sync + fmt::Debug {
    /// Verified plaintext, or `None` when the chunk is not cached.
    fn read(&self, kind: ChunkKind, id: ChunkId) -> Result<Option<Vec<u8>>, SyncError>;
}

impl ChunkReader for VerifiedChunkStore {
    fn read(&self, kind: ChunkKind, id: ChunkId) -> Result<Option<Vec<u8>>, SyncError> {
        match VerifiedChunkStore::get(self, kind, &id) {
            Ok(Some(plain)) => Ok(Some(plain.to_vec())),
            Ok(None) => Ok(None),
            Err(_) => Err(SyncError::ChunkCorrupt { id }),
        }
    }
}

/// The peer side of rsync: it owns the authoritative bytes and returns a
/// delta for the joiner's signature (49 A2).
pub trait DeltaPeer: Send + Sync + fmt::Debug {
    /// Delta for one file segment.
    ///
    /// `offset` and `length` name the segment in the remote file; `signature`
    /// is the joiner's serialized signature over its local basis segment.
    fn delta(
        &self,
        path: &str,
        offset: u64,
        length: usize,
        signature: &[u8],
    ) -> Result<Vec<u8>, SyncError>;
}

/// The remote side of one join, as the applier needs it.
#[derive(Clone, Debug)]
pub struct RemoteView {
    /// Snapshot the view was installed from, when one exists.
    pub reference: Option<crate::protocol::messages::SnapshotRef>,
    /// File-level view.
    pub manifest: Manifest,
    /// Block-level baseline covering every file that needs bytes.
    pub blockmap: Blockmap,
}

/// A prepared remote view plus its content sources.
///
/// This is the seam the client uses between "the join learned what the cluster
/// holds" (W14's `SyncEngine`, or a local fixture) and "the local tree is made
/// to match it" (this module). The trait owns `Arc`s so the apply can run on a
/// blocking worker.
pub trait JoinView: Send + Sync + fmt::Debug {
    /// The authoritative view.
    fn remote(&self) -> RemoteView;
    /// Verified content cache.
    fn chunks(&self) -> Arc<dyn ChunkReader>;
    /// Peer delta source; required only when the view has `ContentDiff` files.
    fn delta(&self) -> Option<Arc<dyn DeltaPeer>>;
}

/// What a cluster-wins apply did.
#[derive(Clone, Debug, Default)]
pub struct ApplyOutcome {
    /// The plan that was executed.
    pub plan: ApplyPlan,
    /// Per-item counters from the apply step.
    pub report: ApplyReport,
    /// Files that came through staging.
    pub staged_files: u64,
    /// Bytes those files hold.
    pub staged_bytes: u64,
    /// Chunks read from the cache.
    pub fetched_chunks: u64,
    /// Files that used the rsync delta path.
    pub rsync_files: u64,
    /// Symlinks created after the file apply.
    pub symlinks: u64,
    /// Manifest entries whose type cannot be represented locally (v1
    /// best-effort: device nodes, sockets, fifos).
    pub skipped: u64,
}

/// The cluster-wins executor.
///
/// It borrows every dependency instead of owning it: the caller decides
/// whether the chunk reader is the real cache and whether a delta peer exists.
/// A plan that needs a missing dependency fails closed; it never falls back to
/// a whole-file fetch (I7).
pub struct ClusterWins<'a> {
    /// Backing root (opened before the mount).
    pub root: &'a Arc<RootFd>,
    /// Authoritative remote manifest.
    pub remote: &'a Manifest,
    /// Block-level baseline for the files that need bytes.
    pub blockmap: &'a Blockmap,
    /// Verified chunk cache.
    pub chunks: &'a dyn ChunkReader,
    /// Peer delta source, required only by `ContentDiff`.
    pub delta: Option<&'a dyn DeltaPeer>,
    /// The only rsync backend.
    pub engine: &'a dyn DeltaEngine,
}

impl fmt::Debug for ClusterWins<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClusterWins")
            .field("at_seq", &self.remote.at_seq)
            .field("delta", &self.delta.is_some())
            .finish_non_exhaustive()
    }
}

impl ClusterWins<'_> {
    /// Execute `plan` against the backing root.
    ///
    /// # Errors
    ///
    /// [`SyncError::ChunkUnavailable`] for a missing chunk,
    /// [`SyncError::ChunkCorrupt`] for a staged block whose hash disagrees
    /// with the blockmap, [`SyncError::StateDigestMismatch`] for a file whose
    /// `file_root` does not match, and I/O errors from staging or apply.
    pub fn apply(&self, plan: &DiffPlan) -> Result<ApplyOutcome, SyncError> {
        let mut outcome = ApplyOutcome::default();
        let mut apply_plan = ApplyPlan::new();
        let mut build = StagingBuild::new(Arc::clone(self.root)).map_err(staging_error)?;

        for item in plan.directories() {
            let entry = self.entry(item)?;
            apply_plan
                .push_mkdir(PathBuf::from(&item.path), entry.mode)
                .map_err(staging_error)?;
        }
        for item in plan.deletions() {
            let dir = item
                .local
                .as_ref()
                .is_some_and(|stat| stat.kind == Kind::Dir);
            apply_plan
                .push_remove(PathBuf::from(&item.path), dir)
                .map_err(staging_error)?;
        }
        for item in plan.attrs() {
            let entry = self.entry(item)?;
            apply_plan
                .push_attrs(
                    PathBuf::from(&item.path),
                    attr_delta(entry, item.local.as_ref()),
                )
                .map_err(staging_error)?;
        }

        // (target, manifest index, item kind) for every staged file.
        let mut staged: Vec<(PathBuf, u32, DiffKind)> = Vec::new();
        // (path, target, existed) for symlinks applied after the file pass.
        let mut symlinks: Vec<(PathBuf, String, bool)> = Vec::new();

        for item in plan.transfers() {
            let index = item
                .remote
                .ok_or(SyncError::Format("transfer without a remote entry"))?;
            let entry = self.entry(item)?;
            match entry.kind {
                Kind::File => {
                    if item.kind == DiffKind::ContentDiff {
                        self.stage_rsync(&mut build, item, entry)?;
                        outcome.rsync_files += 1;
                    } else {
                        outcome.fetched_chunks +=
                            self.stage_chunks(&mut build, item, index, entry)?;
                    }
                    staged.push((PathBuf::from(&item.path), index, item.kind));
                }
                Kind::Symlink => symlinks.push((
                    PathBuf::from(&item.path),
                    entry.target.clone(),
                    item.local.is_some(),
                )),
                Kind::Dir => {
                    // A directory is `DirSync`, never a transfer.
                    outcome.skipped += 1;
                }
                Kind::Char | Kind::Block | Kind::Fifo | Kind::Socket | Kind::Unknown => {
                    // v1 best-effort: the manifest can name these, the local
                    // tree cannot recreate them (39 §4).
                    outcome.skipped += 1;
                }
            }
        }

        let files = build.finish().map_err(staging_error)?;
        let by_target: BTreeMap<&Path, &StagedFile> = files
            .iter()
            .map(|file| (file.target.as_path(), file))
            .collect();
        for (target, index, kind) in &staged {
            let file = by_target
                .get(target.as_path())
                .ok_or(SyncError::Format("staged file missing after finish"))?;
            self.verify_staged(file, *index)?;
            match kind {
                DiffKind::RemoteOnly => apply_plan
                    .push_install(file.staging.clone(), file.target.clone())
                    .map_err(staging_error)?,
                DiffKind::ContentDiff => apply_plan
                    .push_install(file.staging.clone(), file.target.clone())
                    .map_err(staging_error)?,
                DiffKind::TypeReplace => apply_plan
                    .push_type_replace(file.staging.clone(), file.target.clone())
                    .map_err(staging_error)?,
                DiffKind::Identical
                | DiffKind::AttrsOnly
                | DiffKind::LocalOnly
                | DiffKind::DirSync => {
                    return Err(SyncError::Format("non-transfer item reached staging"));
                }
            }
            outcome.staged_files += 1;
            outcome.staged_bytes = outcome.staged_bytes.saturating_add(file.bytes);
        }

        outcome.report = apply(self.root, &apply_plan).map_err(staging_error)?;
        outcome.plan = apply_plan;

        for (path, target, existed) in symlinks {
            if existed {
                self.trash(&path)?;
            }
            self.root
                .symlink_at(Path::new(&target), &path)
                .map_err(SyncError::from)?;
            outcome.symlinks += 1;
        }
        if outcome.symlinks > 0 {
            self.root.syncfs().map_err(SyncError::from)?;
        }
        Ok(outcome)
    }

    fn entry(&self, item: &PlanItem) -> Result<&Entry, SyncError> {
        item.remote
            .and_then(|index| self.remote.entry(index))
            .ok_or(SyncError::Format("plan item names no remote entry"))
    }

    /// Stage a whole file from content-addressed chunks.
    fn stage_chunks(
        &self,
        build: &mut StagingBuild,
        item: &PlanItem,
        index: u32,
        entry: &Entry,
    ) -> Result<u64, SyncError> {
        let blocks = self
            .blockmap
            .file_blocks(index)
            .ok_or(SyncError::Format("blockmap part missing for a transfer"))?;
        if blocks.len() as u32 != entry.block_count {
            return Err(SyncError::Format("blockmap disagrees with manifest"));
        }
        let target = Path::new(&item.path);
        if blocks.is_empty() {
            build
                .stage_bytes(target, &[], entry.mode)
                .map_err(staging_error)?;
            return Ok(0);
        }
        let mut fetched = 0u64;
        for id in blocks {
            let plain = self
                .chunks
                .read(ChunkKind::File, id)?
                .ok_or(SyncError::ChunkUnavailable { id })?;
            if ChunkId::of_plaintext(&plain) != id {
                return Err(SyncError::ChunkCorrupt { id });
            }
            build
                .stage_bytes(target, &plain, entry.mode)
                .map_err(staging_error)?;
            fetched += 1;
        }
        Ok(fetched)
    }

    /// Stage a `ContentDiff` file through the W15 three-step rsync.
    fn stage_rsync(
        &self,
        build: &mut StagingBuild,
        item: &PlanItem,
        entry: &Entry,
    ) -> Result<(), SyncError> {
        let peer = self
            .delta
            .ok_or_else(|| SyncError::Link("content diff needs a delta peer".to_owned()))?;
        let target = Path::new(&item.path);
        let mut offset = 0u64;
        while offset < entry.size {
            let length = (entry.size - offset).min(SEGMENT_BYTES as u64) as usize;
            let basis = read_range(self.root, target, offset, length)?;
            let signature = self.engine.signature(&basis).map_err(delta_error)?;
            let delta = peer.delta(&item.path, offset, length, &signature)?;
            let patched = self.engine.patch(&basis, &delta).map_err(delta_error)?;
            if patched.len() != length {
                return Err(SyncError::Format("rsync segment length mismatch"));
            }
            build
                .stage_segment(target, offset, &patched, entry.mode)
                .map_err(staging_error)?;
            offset += length as u64;
        }
        if entry.size == 0 {
            build
                .stage_bytes(target, &[], entry.mode)
                .map_err(staging_error)?;
        }
        Ok(())
    }

    /// Re-hash a staged file into 256 KiB blocks and check `file_root`.
    fn verify_staged(&self, file: &StagedFile, index: u32) -> Result<(), SyncError> {
        let entry = self
            .remote
            .entry(index)
            .ok_or(SyncError::Format("staged file names no remote entry"))?;
        let expected = self
            .blockmap
            .file_blocks(index)
            .ok_or(SyncError::Format("blockmap part missing for verification"))?;
        if expected.len() as u32 != entry.block_count {
            return Err(SyncError::Format("blockmap disagrees with manifest"));
        }
        let fd = self.root.open_at(
            &file.staging,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let mut ids = Vec::with_capacity(expected.len());
        let mut offset = 0u64;
        let mut buffer = vec![0u8; CHUNK_BYTES];
        loop {
            let count = read_fd(&fd, &mut buffer, offset)?;
            if count == 0 {
                break;
            }
            ids.push(ChunkId::of_plaintext(&buffer[..count]));
            offset += count as u64;
            if count < CHUNK_BYTES {
                break;
            }
        }
        if offset != entry.size {
            return Err(SyncError::StateDigestMismatch);
        }
        if ids != expected {
            let bad = ids
                .iter()
                .zip(expected.iter())
                .find(|(found, wanted)| found != wanted)
                .map(|(found, _)| *found)
                .or_else(|| ids.first().copied())
                .or_else(|| expected.first().copied())
                .ok_or(SyncError::StateDigestMismatch)?;
            return Err(SyncError::ChunkCorrupt { id: bad });
        }
        if file_root(&ids) != entry.file_root {
            return Err(SyncError::StateDigestMismatch);
        }
        Ok(())
    }

    /// Move an existing item to `trash/` before a symlink replaces it.
    fn trash(&self, path: &Path) -> Result<PathBuf, SyncError> {
        ensure_layout(self.root).map_err(staging_error)?;
        let mut seq = 0u64;
        loop {
            let trash = Path::new(TRASH_DIR).join(format!("join-{seq}"));
            match self.root.stat_at(&trash, false) {
                Err(err) if err == Errno::ENOENT => {
                    self.root.rename_at(path, &trash, RenameFlags::NONE)?;
                    return Ok(trash);
                }
                Ok(_) => {
                    seq = seq.saturating_add(1);
                    if seq == u64::MAX {
                        return Err(SyncError::Io("trash name space exhausted".to_owned()));
                    }
                }
                Err(err) => return Err(err.into()),
            }
        }
    }
}

fn attr_delta(entry: &Entry, local: Option<&crate::sync::DiskStat>) -> AttrDelta {
    let Some(local) = local else {
        return AttrDelta::default();
    };
    AttrDelta {
        mode: (local.mode != entry.mode).then_some(entry.mode),
        uid: (local.uid != entry.uid).then_some(entry.uid),
        gid: (local.gid != entry.gid).then_some(entry.gid),
        size: None,
        atime: None,
        mtime: (local.mtime_ns != entry.mtime_ns).then_some(timespec(entry.mtime_ns)),
    }
}

fn timespec(ns: u64) -> Timespec {
    Timespec::new(
        i64::try_from(ns / 1_000_000_000).unwrap_or(i64::MAX),
        (ns % 1_000_000_000) as i64,
    )
}

fn staging_error(err: crate::sync::staging::StagingError) -> SyncError {
    SyncError::Io(err.to_string())
}

fn delta_error(err: crate::sync::rsync::DeltaError) -> SyncError {
    SyncError::Io(err.to_string())
}

fn read_range(
    root: &RootFd,
    path: &Path,
    offset: u64,
    length: usize,
) -> Result<Vec<u8>, SyncError> {
    let fd = match root.open_at(path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()) {
        Ok(fd) => fd,
        Err(err) if err == Errno::ENOENT => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    let mut out = vec![0u8; length];
    let count = read_fd(&fd, &mut out, offset)?;
    out.truncate(count);
    Ok(out)
}

fn read_fd(fd: &std::os::fd::OwnedFd, buffer: &mut [u8], offset: u64) -> Result<usize, SyncError> {
    let mut read = 0usize;
    while read < buffer.len() {
        let count = rustix::io::pread(fd, &mut buffer[read..], offset + read as u64)
            .map_err(Errno::from)?;
        if count == 0 {
            break;
        }
        read += count;
    }
    Ok(read)
}

fn write_file(root: &RootFd, rel: &Path, bytes: &[u8]) -> Result<(), SyncError> {
    let fd = root.open_at(
        rel,
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?;
    let mut at = 0usize;
    while at < bytes.len() {
        let written = rustix::io::write(&fd, &bytes[at..]).map_err(Errno::from)?;
        if written == 0 {
            return Err(SyncError::Io("short journal write".to_owned()));
        }
        at += written;
    }
    rustix::fs::fsync(&fd).map_err(Errno::from)?;
    Ok(())
}

fn read_file(root: &RootFd, rel: &Path) -> Result<Option<Vec<u8>>, SyncError> {
    use std::io::Read;

    let fd = match root.open_at(rel, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()) {
        Ok(fd) => fd,
        Err(err) if err == Errno::ENOENT => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let mut file = std::fs::File::from(fd);
    let mut out = Vec::new();
    file.read_to_end(&mut out)?;
    Ok(Some(out))
}

// ---------------------------------------------------------------------------
// Local tree adapter
// ---------------------------------------------------------------------------

/// A [`LocalTree`](crate::sync::LocalTree) over a backing root.
///
/// Reserved names are filtered at every depth: `.syncmount-staging`,
/// `.syncmount-manifest`, `.audit.log` and `.syncmount` are internal state,
/// never user content, so the diff neither sees nor deletes them (C-10).
#[derive(Debug)]
pub struct DiskTree<'a> {
    root: &'a RootFd,
    cluster: Option<crate::protocol::crypto::ClusterId>,
}

impl<'a> DiskTree<'a> {
    /// Bind the view; without a cluster id the manifest cache is ignored.
    pub const fn new(
        root: &'a RootFd,
        cluster: Option<crate::protocol::crypto::ClusterId>,
    ) -> Self {
        Self { root, cluster }
    }

    fn describe(&self, path: &Path, attr: crate::store::Attr) -> Result<DiskStat, SyncError> {
        let kind = attr.kind();
        let (target, dangling) = if kind == Kind::Symlink {
            let target = self
                .root
                .readlink_at(path)
                .ok()
                .map(|value| value.to_string_lossy().into_owned());
            let dangling = self.root.stat_at(path, true).is_err();
            (target, dangling)
        } else {
            (None, false)
        };
        Ok(DiskStat {
            kind,
            size: attr.size,
            mtime_ns: nanoseconds(attr.mtime),
            mode: attr.perm(),
            uid: attr.uid,
            gid: attr.gid,
            target,
            dangling,
        })
    }
}

impl crate::sync::LocalTree for DiskTree<'_> {
    fn walk(&self) -> Result<Vec<(String, DiskStat)>, SyncError> {
        let entries = self.root.walk_at(Path::new(".")).map_err(SyncError::from)?;
        let mut out = Vec::with_capacity(entries.len());
        for (path, attr) in entries {
            if path.as_os_str() == "." {
                continue;
            }
            let Some(text) = path.to_str() else {
                return Err(SyncError::Local("non-UTF-8 path".to_owned()));
            };
            if text
                .split('/')
                .any(|part| crate::store::is_reserved_name(std::ffi::OsStr::new(part)))
            {
                continue;
            }
            out.push((text.to_owned(), self.describe(&path, attr)?));
        }
        out.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        Ok(out)
    }

    fn stat(&self, path: &str) -> Result<Option<DiskStat>, SyncError> {
        match self.root.stat_at(Path::new(path), false) {
            Ok(attr) => Ok(Some(self.describe(Path::new(path), attr)?)),
            Err(err) if err == Errno::ENOENT => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    fn cached_manifest(&self) -> Option<crate::sync::LocalManifest> {
        self.cluster
            .and_then(|cluster| crate::sync::LocalManifest::load(self.root, cluster))
    }
}

fn nanoseconds(time: Timespec) -> u64 {
    let seconds = time.sec.saturating_mul(1_000_000_000);
    let total = seconds.saturating_add(time.nsec);
    u64::try_from(total).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::collections::BTreeSet;
    use std::sync::Arc;

    use tempfile::TempDir;

    use super::*;
    use crate::protocol::crypto::ClusterId;
    use crate::store::chunk_store::CHUNK_BYTES;
    use crate::store::node_table::InodeId;
    use crate::sync::chunk::ChunkCipher;
    use crate::sync::manifest::{LocalManifest, diff};
    use crate::sync::rsync::OxideEngine;

    const CLUSTER: ClusterId = ClusterId::from_bytes([0x2a; 16]);
    const KEY: [u8; 32] = [0x21; 32];
    const MTIME: u64 = 1_700_000_000_000_000_000;

    fn setup() -> (TempDir, Arc<RootFd>) {
        let tmp = TempDir::new().unwrap();
        let mount = tmp.path().join("mnt");
        std::fs::create_dir(&mount).unwrap();
        let root = Arc::new(RootFd::open_before_mount(&mount).unwrap());
        (tmp, root)
    }

    #[derive(Debug, Default)]
    struct SetCache(BTreeSet<(u8, ChunkId)>);

    impl SetCache {
        fn add(&mut self, kind: ChunkKind, id: ChunkId) {
            self.0.insert((kind.wire(), id));
        }
    }

    impl ChunkPresence for SetCache {
        fn has(&self, kind: ChunkKind, id: ChunkId) -> bool {
            self.0.contains(&(kind.wire(), id))
        }
    }

    #[derive(Debug)]
    struct EmptyReader;

    impl ChunkReader for EmptyReader {
        fn read(&self, _kind: ChunkKind, _id: ChunkId) -> Result<Option<Vec<u8>>, SyncError> {
            Ok(None)
        }
    }

    /// 45:F19 / 43 §5.5 — the journal survives every phase and is never
    /// authoritative.
    #[test]
    fn u_resume_journal_round_trip() {
        let (_tmp, root) = setup();
        let mut state = SyncState::new();
        state.set_session(SessionId::new(9), 7);
        state.note_snapshot(Seq(4096));
        state.note_manifest(Seq(5000), [3u8; 32]);

        let events = [
            SyncEvent::Welcome,
            SyncEvent::SnapshotRef,
            SyncEvent::SnapshotSelected,
            SyncEvent::PartsComplete,
            SyncEvent::Installed,
            SyncEvent::ManifestDone,
            SyncEvent::Planned,
            SyncEvent::AllFilesDone,
            SyncEvent::Staged,
            SyncEvent::Durable,
            SyncEvent::Applied,
            SyncEvent::Committed,
        ];
        let mut visited = 1usize;
        for event in events {
            state.advance(event).unwrap();
            visited += 1;
            let bytes = state.encode();
            let decoded = SyncState::decode(&bytes).unwrap();
            assert_eq!(decoded.phase(), state.phase(), "event {}", event.name());
            assert_eq!(decoded.session_id(), state.session_id());
            assert_eq!(decoded.epoch(), state.epoch());
            assert_eq!(decoded.covered_seq(), state.covered_seq());
            assert_eq!(decoded.at_seq(), state.at_seq());
            assert_eq!(decoded.manifest_root(), state.manifest_root());
            state.save(&root).unwrap();
            assert_eq!(SyncState::load(&root).unwrap().phase(), state.phase());
        }
        assert_eq!(visited, 13);
        assert_eq!(state.phase(), SyncPhase::Online);
        assert!(state.completed(SyncPhase::Apply));
        assert!(!state.completed(SyncPhase::Online));
    }

    /// 43 §8.1 — `Failing` remembers its resume target across a restart.
    #[test]
    fn u_resume_journal_failing_keeps_target() {
        let (_tmp, root) = setup();
        let mut state = SyncState::new();
        for event in [
            SyncEvent::Welcome,
            SyncEvent::SnapshotRef,
            SyncEvent::SnapshotSelected,
            SyncEvent::PartsComplete,
            SyncEvent::Installed,
        ] {
            state.advance(event).unwrap();
        }
        assert_eq!(state.phase(), SyncPhase::ManifestFetch);
        state.advance(SyncEvent::Retry).unwrap();
        state.save(&root).unwrap();

        let loaded = SyncState::load(&root).unwrap();
        assert_eq!(loaded.phase(), SyncPhase::Failing);
        assert_eq!(loaded.resume_target(), Some(SyncPhase::ManifestFetch));
        let mut loaded = loaded;
        assert_eq!(
            loaded.advance(SyncEvent::Resume).unwrap(),
            SyncPhase::ManifestFetch
        );
    }

    /// 45:§4.2 — every phase has a stable journal code, and `Aborted` is a
    /// terminal checkpoint.
    #[test]
    fn u_resume_phase_codes_cover_every_phase() {
        for phase in SyncPhase::ALL {
            assert_eq!(phase_from(phase_code(phase)), Some(phase), "{phase:?}");
        }
        assert_eq!(phase_from(PHASE_NONE), None);

        let mut state = SyncState::new();
        state.advance(SyncEvent::Welcome).unwrap();
        state.advance(SyncEvent::Abort).unwrap();
        let loaded = SyncState::decode(&state.encode()).unwrap();
        assert_eq!(loaded.phase(), SyncPhase::Aborted);
        assert!(!loaded.completed(SyncPhase::Idle));
    }

    /// A damaged journal is ignored, never trusted partially.
    #[test]
    fn u_resume_journal_rejects_damage() {
        let (_tmp, root) = setup();
        let mut state = SyncState::new();
        state.advance(SyncEvent::Welcome).unwrap();
        let mut bytes = state.encode();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(SyncState::decode(&bytes).is_err());
        assert!(SyncState::decode(&state.encode()[..40]).is_err());

        state.save(&root).unwrap();
        assert!(SyncState::load(&root).is_some());
        SyncState::discard(&root).unwrap();
        assert!(SyncState::load(&root).is_none());
        SyncState::discard(&root).unwrap();
    }

    fn resume_fixture() -> (Manifest, Blockmap, ChunkId, ChunkId, ChunkId) {
        let a = ChunkId::of_plaintext(b"a");
        let b = ChunkId::of_plaintext(b"b");
        let c = ChunkId::of_plaintext(b"c");
        let entries = vec![
            Entry::file("a", InodeId(1), 0o644, 1000, 1000, 10, 1, &[a]),
            Entry::file(
                "b",
                InodeId(2),
                0o644,
                1000,
                1000,
                CHUNK_BYTES as u64 + 10,
                2,
                &[b, c],
            ),
            Entry::dir("d", InodeId(3), 0o755, 1000, 1000, 3),
        ];
        let manifest = Manifest::new(Seq(7), entries);
        let blockmap = Blockmap::new(Seq(7), vec![0, 1, 3], vec![a, b, c]).unwrap();
        (manifest, blockmap, a, b, c)
    }

    /// 43 I6 / C-32 — needed and received are derived, and marks are not
    /// authority.
    #[test]
    fn u_resume_derive_and_ledger() {
        let (manifest, blockmap, a, b, c) = resume_fixture();
        let mut cache = SetCache::default();
        cache.add(ChunkKind::File, b);
        let resume = Resume::derive(&manifest, &blockmap, &cache).unwrap();
        assert_eq!(
            resume.needed().collect::<BTreeSet<_>>(),
            BTreeSet::from([a, c])
        );
        assert_eq!(
            resume.received().collect::<BTreeSet<_>>(),
            BTreeSet::from([b])
        );
        assert_eq!(resume.needed_bytes(), 20);
        assert_eq!(resume.received_bytes(), CHUNK_BYTES as u64);
        assert_eq!(resume.file(0).unwrap().needed, 1);
        assert_eq!(resume.file(1).unwrap().received, 1);
        assert_eq!(resume.file(1).unwrap().needed, 1);
        assert_eq!(resume.file(2), None);

        let mut ledger = Ledger::new(resume);
        assert_eq!(ledger.pending_count(), 2);
        assert!(ledger.mark_received(a));
        assert!(!ledger.mark_received(a));
        assert_eq!(ledger.pending_count(), 1);
        assert!(!ledger.is_complete(), "marks must not claim completion");
        ledger.refresh(&manifest, &blockmap, &cache).unwrap();
        assert_eq!(ledger.pending_count(), 2, "refresh discards marks");

        let sparse = Blockmap::sparse(Seq(7), 3, vec![0, 1, 3], Vec::new()).unwrap();
        assert!(Resume::derive(&manifest, &sparse, &cache).is_err());
    }

    fn cached_file(root: &RootFd, manifest: &Manifest) -> LocalManifest {
        let cache = LocalManifest {
            cluster_id: CLUSTER,
            at_seq: manifest.at_seq,
            epoch: 1,
            manifest: manifest.clone(),
        };
        cache.store(root).unwrap();
        cache
    }

    /// 31:M2-8 — a remount deletes local-only entries and keeps reserved
    /// names.
    #[test]
    fn u_resume_cluster_wins_deletes_local_only() {
        let (tmp, root) = setup();
        let mount = tmp.path().join("mnt");
        std::fs::write(mount.join("local-only.txt"), b"local").unwrap();
        std::fs::write(mount.join("keep.txt"), b"same").unwrap();
        std::fs::create_dir(mount.join(".syncmount-staging")).unwrap();

        let attr = root.stat_at(Path::new("keep.txt"), false).unwrap();
        let id = ChunkId::of_plaintext(b"same");
        let entry = Entry::file(
            "keep.txt",
            InodeId(1),
            attr.perm(),
            attr.uid,
            attr.gid,
            attr.size,
            nanoseconds(attr.mtime),
            &[id],
        );
        let manifest = Manifest::new(Seq(1), vec![entry]);
        let blockmap = Blockmap::new(Seq(1), vec![0], vec![id]).unwrap();
        let cache = cached_file(&root, &manifest);
        let tree = DiskTree::new(root.as_ref(), Some(CLUSTER));
        let plan = diff::plan(Some(&cache), &manifest, &tree, CLUSTER).unwrap();
        assert_eq!(plan.counts().local_only, 1);
        assert_eq!(plan.counts().identical, 1);

        let engine = OxideEngine::default();
        let outcome = ClusterWins {
            root: &root,
            remote: &manifest,
            blockmap: &blockmap,
            chunks: &EmptyReader,
            delta: None,
            engine: &engine,
        }
        .apply(&plan)
        .unwrap();
        assert_eq!(outcome.report.removed, 1);
        assert!(!mount.join("local-only.txt").exists());
        assert!(mount.join("keep.txt").exists());
        assert!(mount.join(".syncmount-staging").exists());
    }

    /// 43 I3 — a remote-only file is staged from chunks and verified against
    /// the blockmap before its rename.
    #[test]
    fn u_resume_cluster_wins_installs_remote_file() {
        let (tmp, root) = setup();
        let mount = tmp.path().join("mnt");
        let cipher = ChunkCipher::new(KEY);
        let sealed = cipher.seal(ChunkKind::File, b"hello").unwrap();
        let store = VerifiedChunkStore::open(root.clone(), KEY).unwrap();
        store
            .put_blob(ChunkKind::File, &sealed.chunk_id, &sealed.blob)
            .unwrap();

        let file = Entry::file(
            "dir/f",
            InodeId(1),
            0o644,
            1000,
            1000,
            5,
            MTIME,
            &[sealed.chunk_id],
        );
        let dir = Entry::dir("dir", InodeId(2), 0o755, 1000, 1000, MTIME);
        let manifest = Manifest::new(Seq(2), vec![file, dir]);
        let blockmap = Blockmap::new(Seq(2), vec![0, 0], vec![sealed.chunk_id]).unwrap();
        let tree = DiskTree::new(root.as_ref(), Some(CLUSTER));
        let plan = diff::plan(None, &manifest, &tree, CLUSTER).unwrap();
        assert_eq!(plan.counts().remote_only, 1);
        assert_eq!(plan.counts().dir_sync, 1);

        let engine = OxideEngine::default();
        let outcome = ClusterWins {
            root: &root,
            remote: &manifest,
            blockmap: &blockmap,
            chunks: &store,
            delta: None,
            engine: &engine,
        }
        .apply(&plan)
        .unwrap();
        assert_eq!(outcome.staged_files, 1);
        assert_eq!(outcome.report.installed, 1);
        assert_eq!(outcome.report.dirs, 1);
        assert_eq!(std::fs::read(mount.join("dir/f")).unwrap(), b"hello");
    }

    /// 49 A2 — `ContentDiff` runs signature → peer delta → patch, then
    /// verifies the file root.
    #[test]
    fn u_resume_cluster_wins_rsync_content_diff() {
        let (tmp, root) = setup();
        let mount = tmp.path().join("mnt");
        let remote_bytes = b"hello brave world".to_vec();
        std::fs::write(mount.join("f"), b"hello world").unwrap();

        let id = ChunkId::of_plaintext(&remote_bytes);
        let entry = Entry::file(
            "f",
            InodeId(1),
            0o644,
            1000,
            1000,
            remote_bytes.len() as u64,
            MTIME,
            &[id],
        );
        let manifest = Manifest::new(Seq(3), vec![entry]);
        let blockmap = Blockmap::new(Seq(3), vec![0], vec![id]).unwrap();
        let tree = DiskTree::new(root.as_ref(), Some(CLUSTER));
        let plan = diff::plan(None, &manifest, &tree, CLUSTER).unwrap();
        assert_eq!(plan.counts().content_diff, 1);

        #[derive(Debug)]
        struct Peer {
            bytes: Vec<u8>,
            engine: OxideEngine,
        }
        impl DeltaPeer for Peer {
            fn delta(
                &self,
                _path: &str,
                offset: u64,
                length: usize,
                signature: &[u8],
            ) -> Result<Vec<u8>, SyncError> {
                let start = usize::try_from(offset)
                    .map_err(|_| SyncError::Format("segment offset overflows usize"))?;
                let end = start + length;
                let segment = self
                    .bytes
                    .get(start..end)
                    .ok_or(SyncError::Format("peer segment out of range"))?;
                self.engine.delta(signature, segment).map_err(delta_error)
            }
        }

        let peer = Peer {
            bytes: remote_bytes.clone(),
            engine: OxideEngine::default(),
        };
        let engine = OxideEngine::default();
        let outcome = ClusterWins {
            root: &root,
            remote: &manifest,
            blockmap: &blockmap,
            chunks: &EmptyReader,
            delta: Some(&peer),
            engine: &engine,
        }
        .apply(&plan)
        .unwrap();
        assert_eq!(outcome.rsync_files, 1);
        assert_eq!(outcome.staged_files, 1);
        assert_eq!(std::fs::read(mount.join("f")).unwrap(), remote_bytes);
    }

    /// 43 I3 — a staged file whose root disagrees with the manifest is never
    /// renamed into place.
    #[test]
    fn u_resume_cluster_wins_rejects_bad_file_root() {
        let (tmp, root) = setup();
        let mount = tmp.path().join("mnt");
        let remote_bytes = b"hello brave world".to_vec();
        std::fs::write(mount.join("f"), b"hello world").unwrap();
        let id = ChunkId::of_plaintext(&remote_bytes);
        let mut entry = Entry::file(
            "f",
            InodeId(1),
            0o644,
            1000,
            1000,
            remote_bytes.len() as u64,
            MTIME,
            &[id],
        );
        entry.file_root = [0u8; 32];
        let manifest = Manifest::new(Seq(3), vec![entry]);
        let blockmap = Blockmap::new(Seq(3), vec![0], vec![id]).unwrap();
        let tree = DiskTree::new(root.as_ref(), Some(CLUSTER));
        let plan = diff::plan(None, &manifest, &tree, CLUSTER).unwrap();

        #[derive(Debug)]
        struct Peer {
            bytes: Vec<u8>,
            engine: OxideEngine,
        }
        impl DeltaPeer for Peer {
            fn delta(
                &self,
                _path: &str,
                offset: u64,
                length: usize,
                signature: &[u8],
            ) -> Result<Vec<u8>, SyncError> {
                let start = usize::try_from(offset)
                    .map_err(|_| SyncError::Format("segment offset overflows usize"))?;
                let end = start + length;
                let segment = self
                    .bytes
                    .get(start..end)
                    .ok_or(SyncError::Format("peer segment out of range"))?;
                self.engine.delta(signature, segment).map_err(delta_error)
            }
        }
        let peer = Peer {
            bytes: remote_bytes,
            engine: OxideEngine::default(),
        };
        let engine = OxideEngine::default();
        let error = ClusterWins {
            root: &root,
            remote: &manifest,
            blockmap: &blockmap,
            chunks: &EmptyReader,
            delta: Some(&peer),
            engine: &engine,
        }
        .apply(&plan)
        .unwrap_err();
        assert_eq!(error, SyncError::StateDigestMismatch);
        assert_eq!(std::fs::read(mount.join("f")).unwrap(), b"hello world");
    }
}
