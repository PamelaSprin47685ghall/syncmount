//! Conversion boundary to the P1A value types.
//!
//! The wire types in this module are independent of `mmap::types`,
//! `mmap::manifest` and `mmap::base`. That is deliberate: the wire contract
//! must not drift when a database record gains a field.
//!
//! P1A has landed, so the conversions are real:
//!
//! * [`MmBaseWire`] ↔ [`p1a::MmBase`]. P1A's base has no snapshot sequence or
//!   directory inode, so [`MmBaseWire::from_p1a`] takes those two values
//!   explicitly and `From<MmBaseWire>` drops them. The wire keeps them because
//!   `SNAPSHOT`, `LOCK_GRANTED` and `DIR_VERSION` all report them.
//! * [`Entry`] ↔ [`p1a::ManifestEntry`]. Both directions are `TryFrom`:
//!   the wire allows a new entry without an inode or file root, while P1A
//!   requires both; P1A stores `mtime_ns` as `i64`, the wire as `u64`.
//! * [`ManifestEntryWire`] is the op-free view. P1A can convert to and from it
//!   without importing the manifest-only `op`/`from_name` fields.
//! * [`ManifestEntrySource`] lets a P1A entry feed [`Entry::from_source`]
//!   without this module naming the P1A type in the signature.

use crate::mmap::base;
use crate::mmap::types as p1a;

use super::error::ProtoError;
use super::messages::Snapshot;
use super::types::{
    DirAttrs, Entry, EntryKind, EntryOp, ManifestEntrySource, ManifestEntryWire, MmBaseWire,
};
use super::upload::{DirVersion, LockGranted};

impl Snapshot {
    /// The base triple this snapshot describes.
    pub fn mm_base(&self) -> MmBaseWire {
        MmBaseWire {
            epoch: self.epoch,
            base_seq: self.base_seq,
            snapshot_seq: self.snapshot_seq,
            dir_ino: self.dir_ino,
            dir_version: self.dir_version,
        }
    }
}

impl From<&Snapshot> for MmBaseWire {
    fn from(snapshot: &Snapshot) -> Self {
        snapshot.mm_base()
    }
}

impl From<&LockGranted> for MmBaseWire {
    fn from(granted: &LockGranted) -> Self {
        granted.mm_base()
    }
}

impl From<&DirVersion> for MmBaseWire {
    fn from(version: &DirVersion) -> Self {
        version.mm_base()
    }
}

impl MmBaseWire {
    /// Build a wire base from P1A's triple plus the two values P1A does not
    /// store in `MmBase`.
    pub fn from_p1a(base: &p1a::MmBase, snapshot_seq: u64, dir_ino: [u8; 16]) -> Self {
        Self {
            epoch: base.epoch,
            base_seq: base.dir_seq.get(),
            snapshot_seq,
            dir_ino,
            dir_version: base.dir_version,
        }
    }
}

impl From<MmBaseWire> for p1a::MmBase {
    fn from(wire: MmBaseWire) -> Self {
        Self::new(
            wire.epoch,
            p1a::DirSeq::new(wire.base_seq),
            wire.dir_version,
        )
    }
}

impl TryFrom<&p1a::DirAttrs> for DirAttrs {
    type Error = ProtoError;

    fn try_from(attrs: &p1a::DirAttrs) -> Result<Self, Self::Error> {
        Ok(Self {
            mode: attrs.mode,
            uid: attrs.uid,
            gid: attrs.gid,
            mtime_ns: u64::try_from(attrs.mtime_ns)
                .map_err(|_| ProtoError::Inconsistent("negative mtime"))?,
        })
    }
}

impl TryFrom<DirAttrs> for p1a::DirAttrs {
    type Error = ProtoError;

    fn try_from(attrs: DirAttrs) -> Result<Self, Self::Error> {
        Ok(Self {
            mode: attrs.mode,
            uid: attrs.uid,
            gid: attrs.gid,
            mtime_ns: i64::try_from(attrs.mtime_ns)
                .map_err(|_| ProtoError::Inconsistent("mtime overflows i64"))?,
        })
    }
}

fn wire_kind(kind: p1a::EntryKind) -> EntryKind {
    match kind {
        p1a::EntryKind::File => EntryKind::File,
        p1a::EntryKind::Symlink => EntryKind::Symlink,
        p1a::EntryKind::Dir => EntryKind::Dir,
    }
}

fn p1a_kind(kind: EntryKind) -> p1a::EntryKind {
    match kind {
        EntryKind::File => p1a::EntryKind::File,
        EntryKind::Symlink => p1a::EntryKind::Symlink,
        EntryKind::Dir => p1a::EntryKind::Dir,
    }
}

fn wire_op(op: p1a::EntryOp) -> EntryOp {
    match op {
        p1a::EntryOp::Keep => EntryOp::Keep,
        p1a::EntryOp::Put => EntryOp::Put,
        p1a::EntryOp::Delete => EntryOp::Delete,
        p1a::EntryOp::Rename => EntryOp::Rename,
        p1a::EntryOp::DirAdd => EntryOp::DirAdd,
        p1a::EntryOp::DirRemove => EntryOp::DirRemove,
        p1a::EntryOp::DirRename => EntryOp::DirRename,
    }
}

fn p1a_op(op: EntryOp) -> p1a::EntryOp {
    match op {
        EntryOp::Keep => p1a::EntryOp::Keep,
        EntryOp::Put => p1a::EntryOp::Put,
        EntryOp::Delete => p1a::EntryOp::Delete,
        EntryOp::Rename => p1a::EntryOp::Rename,
        EntryOp::DirAdd => p1a::EntryOp::DirAdd,
        EntryOp::DirRemove => p1a::EntryOp::DirRemove,
        EntryOp::DirRename => p1a::EntryOp::DirRename,
    }
}

impl ManifestEntrySource for p1a::ManifestEntry {
    fn name(&self) -> &str {
        &self.name
    }

    fn ino(&self) -> Option<[u8; 16]> {
        Some(self.ino)
    }

    fn kind(&self) -> EntryKind {
        wire_kind(self.kind)
    }

    fn mode(&self) -> u32 {
        self.mode
    }

    fn uid(&self) -> u32 {
        self.uid
    }

    fn gid(&self) -> u32 {
        self.gid
    }

    fn mtime_ns(&self) -> u64 {
        u64::try_from(self.mtime_ns).unwrap_or(0)
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn file_root(&self) -> Option<[u8; 32]> {
        Some(self.file_root)
    }

    fn content_hash(&self) -> Option<[u8; 32]> {
        self.content_hash
    }

    fn target(&self) -> Option<&[u8]> {
        self.target.as_deref()
    }
}

impl TryFrom<&p1a::ManifestEntry> for Entry {
    type Error = ProtoError;

    fn try_from(source: &p1a::ManifestEntry) -> Result<Self, Self::Error> {
        let entry = Self {
            name: source.name.clone(),
            ino: Some(source.ino),
            kind: wire_kind(source.kind),
            op: wire_op(source.op),
            from_name: source.from_name.clone(),
            mode: source.mode,
            uid: source.uid,
            gid: source.gid,
            mtime_ns: u64::try_from(source.mtime_ns)
                .map_err(|_| ProtoError::Inconsistent("negative mtime"))?,
            size: source.size,
            file_root: Some(source.file_root),
            content_hash: source.content_hash,
            target: source.target.clone(),
        };
        entry.validate_basic()?;
        Ok(entry)
    }
}

impl TryFrom<&Entry> for p1a::ManifestEntry {
    type Error = ProtoError;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        entry.validate_basic()?;
        let ino = entry
            .ino
            .ok_or(ProtoError::Inconsistent("wire entry lacks ino"))?;
        let file_root = match entry.kind {
            EntryKind::Dir => entry.file_root.unwrap_or_else(base::dir_root),
            EntryKind::Symlink => match entry.file_root {
                Some(root) => root,
                None => base::symlink_root(
                    entry
                        .target
                        .as_deref()
                        .ok_or(ProtoError::Inconsistent("symlink lacks target"))?,
                ),
            },
            EntryKind::File => entry
                .file_root
                .ok_or(ProtoError::Inconsistent("file entry lacks file_root"))?,
        };
        Ok(Self {
            name: entry.name.clone(),
            ino,
            kind: p1a_kind(entry.kind),
            op: p1a_op(entry.op),
            from_name: entry.from_name.clone(),
            mode: entry.mode,
            uid: entry.uid,
            gid: entry.gid,
            mtime_ns: i64::try_from(entry.mtime_ns)
                .map_err(|_| ProtoError::Inconsistent("mtime overflows i64"))?,
            size: entry.size,
            file_root,
            content_hash: entry.content_hash,
            target: entry.target.clone(),
        })
    }
}

impl TryFrom<&p1a::ManifestEntry> for ManifestEntryWire {
    type Error = ProtoError;

    fn try_from(source: &p1a::ManifestEntry) -> Result<Self, Self::Error> {
        let entry = Entry::try_from(source)?;
        Ok(entry.manifest_entry())
    }
}

impl ManifestEntryWire {
    /// Turn the P1A-facing view back into a wire entry with an explicit op.
    ///
    /// # Errors
    ///
    /// Any [`Entry::validate_basic`] error.
    pub fn into_entry(self, op: EntryOp) -> Result<Entry, ProtoError> {
        let entry = Entry {
            name: self.name,
            ino: self.ino,
            kind: self.kind,
            op,
            from_name: None,
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            mtime_ns: self.mtime_ns,
            size: self.size,
            file_root: self.file_root,
            content_hash: self.content_hash,
            target: self.target,
        };
        entry.validate_basic()?;
        Ok(entry)
    }
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::mmap::proto::Limits;
    use crate::mmap::proto::types::SignatureState;
    use crate::mmap::proto::upload::{UploadBegin, UploadPlan};

    fn attrs() -> DirAttrs {
        DirAttrs {
            mode: 0o755,
            uid: 1000,
            gid: 1000,
            mtime_ns: 7,
        }
    }

    fn p1a_attrs() -> p1a::DirAttrs {
        p1a::DirAttrs {
            mode: 0o755,
            uid: 1000,
            gid: 1000,
            mtime_ns: 7,
        }
    }

    fn p1a_file() -> p1a::ManifestEntry {
        p1a::ManifestEntry {
            name: "a.txt".to_owned(),
            ino: [0x11; 16],
            kind: p1a::EntryKind::File,
            op: p1a::EntryOp::Put,
            from_name: None,
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            mtime_ns: 9,
            size: 3,
            file_root: [0x22; 32],
            content_hash: Some([0x33; 32]),
            target: None,
        }
    }

    fn p1a_dir() -> p1a::ManifestEntry {
        p1a::ManifestEntry {
            name: "sub".to_owned(),
            ino: [0x44; 16],
            kind: p1a::EntryKind::Dir,
            op: p1a::EntryOp::DirAdd,
            from_name: None,
            mode: 0o755,
            uid: 1000,
            gid: 1000,
            mtime_ns: 9,
            size: 0,
            file_root: base::dir_root(),
            content_hash: None,
            target: None,
        }
    }

    fn p1a_symlink() -> p1a::ManifestEntry {
        p1a::ManifestEntry {
            name: "link".to_owned(),
            ino: [0x55; 16],
            kind: p1a::EntryKind::Symlink,
            op: p1a::EntryOp::Put,
            from_name: None,
            mode: 0o777,
            uid: 1000,
            gid: 1000,
            mtime_ns: 9,
            size: 5,
            file_root: base::symlink_root(b"a.txt"),
            content_hash: None,
            target: Some(b"a.txt".to_vec()),
        }
    }

    #[test]
    fn snapshot_exposes_the_base_triple() {
        let snapshot = Snapshot {
            snapshot_seq: 42,
            epoch: 3,
            base_seq: 7,
            dir_ino: [0x01; 16],
            dir_path: "/a".to_owned(),
            dir_version: [0x02; 32],
            dir_attrs: attrs(),
            entries: Vec::new(),
        };
        let wire = snapshot.mm_base();
        let base: p1a::MmBase = wire.into();
        assert_eq!(base, p1a::MmBase::new(3, p1a::DirSeq::new(7), [0x02; 32]));
        assert_eq!(
            MmBaseWire::from_p1a(&base, 42, [0x01; 16]),
            snapshot.mm_base()
        );
    }

    #[test]
    fn lock_grant_and_dir_version_expose_the_same_shape() {
        let granted = LockGranted {
            lock_id: [0x0A; 16],
            dir_path: "/a".to_owned(),
            dir_ino: [0x01; 16],
            epoch: 3,
            base_seq: 7,
            snapshot_seq: 42,
            dir_version: [0x02; 32],
            expires_at_ms: 1,
            ttl_ms: 2,
        };
        let version = DirVersion {
            epoch: 3,
            snapshot_seq: 42,
            base_seq: 7,
            dir_version: [0x02; 32],
            dir_ino: [0x01; 16],
            dir_path: "/a".to_owned(),
        };
        assert_eq!(MmBaseWire::from(&granted), MmBaseWire::from(&version));
    }

    #[test]
    fn dir_attrs_convert_both_ways_and_reject_negative_mtime() {
        let wire = DirAttrs::try_from(&p1a_attrs()).unwrap();
        assert_eq!(wire, attrs());
        let back = p1a::DirAttrs::try_from(wire).unwrap();
        assert_eq!(back, p1a_attrs());

        let mut negative = p1a_attrs();
        negative.mtime_ns = -1;
        assert!(DirAttrs::try_from(&negative).is_err());

        let mut huge = attrs();
        huge.mtime_ns = u64::MAX;
        assert!(p1a::DirAttrs::try_from(huge).is_err());
    }

    #[test]
    fn manifest_entries_convert_both_ways() {
        for p1a_entry in [p1a_file(), p1a_dir(), p1a_symlink()] {
            let wire = Entry::try_from(&p1a_entry).unwrap();
            let back = p1a::ManifestEntry::try_from(&wire).unwrap();
            assert_eq!(back, p1a_entry);

            let view = ManifestEntryWire::try_from(&p1a_entry).unwrap();
            assert_eq!(view.name, p1a_entry.name);
            let rebuilt = view.into_entry(wire.op).unwrap();
            assert_eq!(rebuilt, wire);
        }
    }

    #[test]
    fn a_directory_entry_uses_the_canonical_dir_root() {
        let wire = Entry::try_from(&p1a_dir()).unwrap();
        assert_eq!(wire.file_root, Some(base::dir_root()));
        let back = p1a::ManifestEntry::try_from(&wire).unwrap();
        assert_eq!(back.file_root, base::dir_root());
    }

    #[test]
    fn wire_entries_without_an_inode_or_root_do_not_convert() {
        let mut wire = Entry::try_from(&p1a_file()).unwrap();
        wire.ino = None;
        assert!(p1a::ManifestEntry::try_from(&wire).is_err());

        let mut wire = Entry::try_from(&p1a_file()).unwrap();
        wire.file_root = None;
        assert!(p1a::ManifestEntry::try_from(&wire).is_err());
    }

    #[test]
    fn manifest_entry_source_feeds_entry_from_source() {
        let p1a_entry = p1a_file();
        let rebuilt = Entry::from_source(&p1a_entry, EntryOp::Put).unwrap();
        assert_eq!(rebuilt, Entry::try_from(&p1a_entry).unwrap());
    }

    #[test]
    fn upload_messages_use_the_wire_types_without_p1a() {
        let begin = UploadBegin {
            namespace: "private-mm".to_owned(),
            dir_path: "/a".to_owned(),
            dir_ino: [0x01; 16],
            epoch: 3,
            base_seq: 7,
            dir_version: [0x02; 32],
            batch_id: [0x03; 16],
            lock_id: [0x04; 16],
            client_id: [0x05; 16],
            manifest_hash: [0x06; 32],
            entries: vec![Entry::try_from(&p1a_file()).unwrap()],
            structural: Vec::new(),
            dir_attrs: attrs(),
            mode: super::super::types::UploadMode::Delta,
        };
        begin.validate().unwrap();
        let plan = UploadPlan {
            batch_id: [0x03; 16],
            epoch: 3,
            base_seq: 7,
            dir_version: [0x02; 32],
            plan: Vec::new(),
            lock_expires_at_ms: 1,
            limits: Limits::new(),
        };
        plan.validate().unwrap();
        assert_eq!(SignatureState::Delta.as_u8(), 2);
    }
}
