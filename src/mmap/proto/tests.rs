//! Cross-message tests: round-trips, strict rejection, limits and MACs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use super::auth::{
    MacParts, SessionGuard, SessionKeys, accept_welcome, derive_hello_key, derive_session_key,
    hash_meta, hash_payload, hello_proof, verify_hello, welcome_proof,
};
use super::error::{AuthError, ErrorCode, ProtoError};
use super::field::FieldWriter;
use super::header::Header;
use super::instruction::{Instruction, InstructionReader, InstructionWriter};
use super::limits::{Limits, MAX_BLOCKS, MAX_DATA, MAX_ENTRIES, MAX_META, MAX_RANGE};
use super::messages::{
    Checkout, FileData, FileRead, Hello, Message, SignatureRequest, Signatures, Snapshot, Welcome,
    decode_frame, encode_frame,
};
use super::stream::{SmmReader, SmmWriter};
use super::types::{
    BatchState, BlockSignature, DirAttrs, Entry, EntryKind, EntryOp, FileSignature, MAX_NAME,
    MAX_PATH, PlanAction, PlanItem, SignatureFile, SignatureState, UploadMode, check_name,
    check_path,
};
use super::upload::{
    Aborted, BatchStateMessage, BatchStatus, DirVersion, DirVersionRequest, ErrorBody, LockAcquire,
    LockGranted, LockRelease, LockReleased, LockRenew, LockRenewed, UploadAbort, UploadBegin,
    UploadCommit, UploadPlan, UploadResult,
};

const MASTER: [u8; 32] = [0x42; 32];
const CLIENT: [u8; 16] = [0x11; 16];
const CLIENT_NONCE: [u8; 32] = [0x22; 32];
const SERVER_NONCE: [u8; 32] = [0x33; 32];
const SESSION: [u8; 16] = [0x44; 16];
const INO: [u8; 16] = [0x55; 16];
const ROOT: [u8; 32] = [0x66; 32];
const HASH: [u8; 32] = [0x77; 32];
const STRONG: [u8; 16] = [0x77; 16];

fn attrs() -> DirAttrs {
    DirAttrs {
        mode: 0o755,
        uid: 1000,
        gid: 1000,
        mtime_ns: 1_700_000_000_000_000_000,
    }
}

fn file_entry(op: EntryOp) -> Entry {
    Entry {
        name: "a.txt".to_owned(),
        ino: Some(INO),
        kind: EntryKind::File,
        op,
        from_name: None,
        mode: 0o644,
        uid: 1000,
        gid: 1000,
        mtime_ns: 7,
        size: 3,
        file_root: Some(ROOT),
        content_hash: if op == EntryOp::Put { Some(HASH) } else { None },
        target: None,
    }
}

fn dir_entry(op: EntryOp) -> Entry {
    Entry {
        name: "sub".to_owned(),
        ino: Some([0x88; 16]),
        kind: EntryKind::Dir,
        op,
        from_name: None,
        mode: 0o755,
        uid: 1000,
        gid: 1000,
        mtime_ns: 7,
        size: 0,
        file_root: None,
        content_hash: None,
        target: None,
    }
}

fn symlink_entry(op: EntryOp) -> Entry {
    Entry {
        name: "link".to_owned(),
        ino: Some([0x99; 16]),
        kind: EntryKind::Symlink,
        op,
        from_name: None,
        mode: 0o777,
        uid: 1000,
        gid: 1000,
        mtime_ns: 7,
        size: 5,
        file_root: Some(ROOT),
        content_hash: None,
        target: Some(b"a.txt".to_vec()),
    }
}

fn hello() -> Hello {
    let key = derive_hello_key(&MASTER);
    Hello {
        client_id: CLIENT,
        client_nonce: CLIENT_NONCE,
        timestamp_ms: 1_000_000,
        proof: hello_proof(&key, &CLIENT, &CLIENT_NONCE, 1_000_000),
    }
}

fn welcome() -> Welcome {
    let key = derive_hello_key(&MASTER);
    let expires = 1_600_000;
    Welcome {
        session_id: SESSION,
        server_nonce: SERVER_NONCE,
        session_expires_at_ms: expires,
        limits: Limits::new(),
        proof: welcome_proof(&key, &CLIENT_NONCE, &SERVER_NONCE, &SESSION, expires),
    }
}

fn checkout() -> Checkout {
    Checkout {
        namespace: "private-mm".to_owned(),
        dir_path: "/a/b".to_owned(),
        bodies: 1,
        if_dir_version: Some([0x0A; 32]),
        if_snapshot_seq: Some(9),
    }
}

fn snapshot() -> Snapshot {
    Snapshot {
        snapshot_seq: 42,
        epoch: 3,
        base_seq: 7,
        dir_ino: INO,
        dir_path: "/a/b".to_owned(),
        dir_version: [0x0B; 32],
        dir_attrs: attrs(),
        entries: vec![file_entry(EntryOp::Keep), symlink_entry(EntryOp::Keep)],
    }
}

fn file_read() -> FileRead {
    FileRead {
        namespace: "private-mm".to_owned(),
        dir_path: "/a/b".to_owned(),
        name: "a.txt".to_owned(),
        ino: INO,
        file_root: ROOT,
        range_offset: 4096,
        range_len: 8192,
    }
}

fn file_data() -> FileData {
    FileData {
        range_offset: 4096,
        range_len: 3,
        range_hash: HASH,
    }
}

fn signature_request() -> SignatureRequest {
    SignatureRequest {
        namespace: "private-mm".to_owned(),
        dir_path: "/a/b".to_owned(),
        dir_ino: INO,
        epoch: 3,
        base_seq: 7,
        dir_version: [0x0B; 32],
        lock_id: [0x0C; 16],
        batch_id: [0x0D; 16],
        files: vec![SignatureFile {
            name: "a.txt".to_owned(),
            ino: Some(INO),
            size: 4096,
            local_file_root: ROOT,
        }],
    }
}

fn signatures() -> Signatures {
    Signatures {
        epoch: 3,
        base_seq: 7,
        dir_version: [0x0B; 32],
        files: vec![FileSignature {
            name: "a.txt".to_owned(),
            ino: INO,
            size: 4096,
            file_root: ROOT,
            state: SignatureState::Delta,
            block_size: 64 * 1024,
            block_count: 1,
            blocks: vec![BlockSignature {
                weak: 0xDEAD_BEEF,
                strong: STRONG,
                block_len: 4096,
            }],
        }],
    }
}

fn upload_begin() -> UploadBegin {
    UploadBegin {
        namespace: "private-mm".to_owned(),
        dir_path: "/a/b".to_owned(),
        dir_ino: INO,
        epoch: 3,
        base_seq: 7,
        dir_version: [0x0B; 32],
        batch_id: [0x0D; 16],
        lock_id: [0x0C; 16],
        client_id: CLIENT,
        manifest_hash: [0x0E; 32],
        entries: vec![file_entry(EntryOp::Put), dir_entry(EntryOp::DirAdd)],
        structural: vec![dir_entry(EntryOp::DirAdd)],
        dir_attrs: attrs(),
        mode: UploadMode::Delta,
    }
}

fn upload_plan() -> UploadPlan {
    UploadPlan {
        batch_id: [0x0D; 16],
        epoch: 3,
        base_seq: 7,
        dir_version: [0x0B; 32],
        plan: vec![
            PlanItem {
                action: PlanAction::PutDelta,
                name: "a.txt".to_owned(),
                reason: Some("changed".to_owned()),
            },
            PlanItem {
                action: PlanAction::DirAdd,
                name: "sub".to_owned(),
                reason: None,
            },
        ],
        lock_expires_at_ms: 1_600_000,
        limits: Limits::new(),
    }
}

fn upload_commit() -> UploadCommit {
    UploadCommit {
        namespace: "private-mm".to_owned(),
        batch_id: [0x0D; 16],
        lock_id: [0x0C; 16],
        epoch: 3,
        base_seq: 7,
        dir_version: [0x0B; 32],
        manifest_hash: [0x0E; 32],
    }
}

fn upload_result() -> UploadResult {
    UploadResult {
        snapshot_seq: 43,
        epoch: 3,
        base_seq_after: 8,
        dir_version_after: [0x0F; 32],
        batch_id: [0x0D; 16],
        entry_count: 2,
        bytes: 4096,
        committed_at_ms: 1_500_000,
    }
}

fn upload_abort() -> UploadAbort {
    UploadAbort {
        batch_id: [0x0D; 16],
        lock_id: [0x0C; 16],
    }
}

fn aborted() -> Aborted {
    Aborted {
        batch_id: [0x0D; 16],
        reason: Some("client cancelled".to_owned()),
    }
}

fn lock_acquire() -> LockAcquire {
    LockAcquire {
        namespace: "private-mm".to_owned(),
        dir_path: "/a/b".to_owned(),
        client_id: CLIENT,
        session_id: SESSION,
        lock_id: Some([0x0C; 16]),
    }
}

fn lock_granted() -> LockGranted {
    LockGranted {
        lock_id: [0x0C; 16],
        dir_path: "/a/b".to_owned(),
        dir_ino: INO,
        epoch: 3,
        base_seq: 7,
        snapshot_seq: 42,
        dir_version: [0x0B; 32],
        expires_at_ms: 1_600_000,
        ttl_ms: 60_000,
    }
}

fn lock_renew() -> LockRenew {
    LockRenew {
        lock_id: [0x0C; 16],
        progress_bytes: Some(8 * 1024 * 1024),
    }
}

fn lock_renewed() -> LockRenewed {
    LockRenewed {
        lock_id: [0x0C; 16],
        expires_at_ms: 1_660_000,
    }
}

fn lock_release() -> LockRelease {
    LockRelease {
        lock_id: [0x0C; 16],
    }
}

fn lock_released() -> LockReleased {
    LockReleased {
        lock_id: [0x0C; 16],
    }
}

fn batch_status() -> BatchStatus {
    BatchStatus {
        batch_id: [0x0D; 16],
    }
}

fn batch_state() -> BatchStateMessage {
    BatchStateMessage {
        batch_id: [0x0D; 16],
        state: BatchState::Committed,
        snapshot_seq: Some(43),
        base_seq_after: Some(8),
        dir_version_after: Some([0x0F; 32]),
        manifest_hash: [0x0E; 32],
        dir_path: "/a/b".to_owned(),
    }
}

fn dir_version_request() -> DirVersionRequest {
    DirVersionRequest {
        namespace: "private-mm".to_owned(),
        dir_ino: INO,
        dir_path: Some("/a/b".to_owned()),
    }
}

fn dir_version() -> DirVersion {
    DirVersion {
        epoch: 3,
        snapshot_seq: 42,
        base_seq: 7,
        dir_version: [0x0B; 32],
        dir_ino: INO,
        dir_path: "/a/b".to_owned(),
    }
}

fn error_body(code: ErrorCode) -> ErrorBody {
    let mut body = ErrorBody::new(code);
    match code {
        ErrorCode::LockHeld => {
            body.owner_client = Some(CLIENT);
            body.expires_at_ms = Some(1_600_000);
            body.retry_after_ms = Some(15_000);
        }
        ErrorCode::LockLost | ErrorCode::LockExpired => {
            body.reason = Some("lease gone".to_owned());
        }
        ErrorCode::BaseChanged => {
            body.epoch = Some(3);
            body.snapshot_seq = Some(42);
            body.base_seq = Some(7);
            body.dir_version = Some([0x0B; 32]);
            body.dir_ino = Some(INO);
            body.request_base_seq = Some(6);
            body.dir_path = Some("/a/b".to_owned());
        }
        ErrorCode::ManifestIncomplete => {
            body.missing = vec!["a.txt".to_owned(), "b.txt".to_owned()];
        }
        ErrorCode::HashMismatch => {
            body.expected = Some(HASH);
            body.actual = Some([0x78; 32]);
            body.retry_full = true;
        }
        _ => {}
    }
    body
}

fn round_trip<M>(message: &M)
where
    M: Message + PartialEq + std::fmt::Debug,
{
    let limits = Limits::new();
    let meta = message.encode_meta().unwrap();
    let decoded = M::decode_meta(&meta).unwrap();
    assert_eq!(&decoded, message);
    let (header, meta2) = encode_frame(message, &limits).unwrap();
    assert_eq!(header.kind, M::KIND);
    assert_eq!(meta, meta2);
    let decoded = decode_frame::<M>(&header, &meta2).unwrap();
    assert_eq!(&decoded, message);
}

#[test]
fn every_message_round_trips() {
    round_trip(&hello());
    round_trip(&welcome());
    round_trip(&checkout());
    round_trip(&snapshot());
    round_trip(&file_read());
    round_trip(&file_data());
    round_trip(&signature_request());
    round_trip(&signatures());
    round_trip(&upload_begin());
    round_trip(&upload_plan());
    round_trip(&upload_commit());
    round_trip(&upload_result());
    round_trip(&upload_abort());
    round_trip(&aborted());
    round_trip(&lock_acquire());
    round_trip(&lock_granted());
    round_trip(&lock_renew());
    round_trip(&lock_renewed());
    round_trip(&lock_release());
    round_trip(&lock_released());
    round_trip(&batch_status());
    round_trip(&batch_state());
    round_trip(&dir_version_request());
    round_trip(&dir_version());

    for code in [
        ErrorCode::BadRequest,
        ErrorCode::AuthFailed,
        ErrorCode::BaseChanged,
        ErrorCode::ManifestIncomplete,
        ErrorCode::HashMismatch,
        ErrorCode::LockHeld,
        ErrorCode::LockLost,
        ErrorCode::LockExpired,
        ErrorCode::TooLarge,
    ] {
        round_trip(&error_body(code));
    }
}

#[test]
fn empty_optional_lists_and_fields_round_trip() {
    round_trip(&Snapshot {
        entries: Vec::new(),
        ..snapshot()
    });
    round_trip(&Checkout {
        if_dir_version: None,
        if_snapshot_seq: None,
        ..checkout()
    });
    round_trip(&UploadBegin {
        entries: Vec::new(),
        structural: Vec::new(),
        ..upload_begin()
    });
    round_trip(&UploadPlan {
        plan: Vec::new(),
        ..upload_plan()
    });
    round_trip(&LockAcquire {
        lock_id: None,
        ..lock_acquire()
    });
    round_trip(&LockRenew {
        progress_bytes: None,
        ..lock_renew()
    });
    round_trip(&Aborted {
        reason: None,
        ..aborted()
    });
}

fn with_extra_field(meta: &[u8]) -> Vec<u8> {
    let mut writer = FieldWriter::new();
    writer.u8(0x01, 0).unwrap();
    let mut bytes = meta.to_vec();
    bytes.extend_from_slice(&writer.into_bytes());
    bytes
}

#[test]
fn unknown_fields_are_rejected_by_every_message() {
    fn rejects_extra<M: Message>(message: &M) {
        let meta = message.encode_meta().unwrap();
        assert!(
            matches!(
                M::decode_meta(&with_extra_field(&meta)),
                Err(ProtoError::UnknownTag(0x01))
            ),
            "{} accepted an unknown tag",
            M::KIND.name()
        );
    }
    rejects_extra(&hello());
    rejects_extra(&welcome());
    rejects_extra(&checkout());
    rejects_extra(&snapshot());
    rejects_extra(&file_read());
    rejects_extra(&file_data());
    rejects_extra(&signature_request());
    rejects_extra(&signatures());
    rejects_extra(&upload_begin());
    rejects_extra(&upload_plan());
    rejects_extra(&upload_commit());
    rejects_extra(&upload_result());
    rejects_extra(&upload_abort());
    rejects_extra(&aborted());
    rejects_extra(&lock_acquire());
    rejects_extra(&lock_granted());
    rejects_extra(&lock_renew());
    rejects_extra(&lock_renewed());
    rejects_extra(&lock_release());
    rejects_extra(&lock_released());
    rejects_extra(&batch_status());
    rejects_extra(&batch_state());
    rejects_extra(&dir_version_request());
    rejects_extra(&dir_version());
    rejects_extra(&error_body(ErrorCode::BadRequest));
}

#[test]
fn header_version_flags_and_reserved_are_rejected() {
    let limits = Limits::new();
    let (header, meta) = encode_frame(&checkout(), &limits).unwrap();
    let mut bytes = header.encode();
    bytes[4] = 2;
    assert!(matches!(
        Header::decode(&bytes),
        Err(ProtoError::UnsupportedVersion(2))
    ));
    let mut bytes = header.encode();
    bytes[5] = 0x42;
    assert!(matches!(
        Header::decode(&bytes),
        Err(ProtoError::UnknownKind(0x42))
    ));
    let mut bytes = header.encode();
    bytes[6] = 1;
    assert!(matches!(
        Header::decode(&bytes),
        Err(ProtoError::ReservedFlags(1))
    ));
    let mut bytes = header.encode();
    bytes[20] = 1;
    assert!(matches!(
        Header::decode(&bytes),
        Err(ProtoError::NonZeroReserved(1))
    ));
    assert!(matches!(
        decode_frame::<Checkout>(&header, &meta[..meta.len() - 1]),
        Err(ProtoError::Truncated { .. })
    ));
}

#[test]
fn a_typed_decoder_rejects_the_wrong_kind() {
    let limits = Limits::new();
    let (header, meta) = encode_frame(&checkout(), &limits).unwrap();
    assert!(matches!(
        decode_frame::<Snapshot>(&header, &meta),
        Err(ProtoError::WrongKind { .. })
    ));
}

#[test]
fn oversized_meta_and_data_are_rejected() {
    let limits = Limits::new();
    assert!(matches!(
        Header::new(super::kind::Kind::Snapshot, MAX_META + 1, 0, &limits),
        Err(ProtoError::MetaTooLarge { .. })
    ));
    assert!(matches!(
        Header::new(super::kind::Kind::Snapshot, 0, MAX_DATA + 1, &limits),
        Err(ProtoError::DataTooLarge { .. })
    ));
}

#[test]
fn oversized_entries_and_blocks_are_rejected() {
    let mut begin = upload_begin();
    begin.entries = vec![file_entry(EntryOp::Put); MAX_ENTRIES as usize + 1];
    begin.structural.clear();
    assert!(matches!(
        begin.encode_meta(),
        Err(ProtoError::TooManyRecords {
            tag: super::tag::ENTRIES,
            ..
        })
    ));

    let mut signatures = signatures();
    signatures.files[0].block_count = MAX_BLOCKS + 1;
    signatures.files[0].blocks.clear();
    assert!(matches!(
        signatures.encode_meta(),
        Err(ProtoError::TooManyRecords {
            tag: super::tag::BLOCKS,
            ..
        })
    ));
}

#[test]
fn oversized_ranges_and_file_sizes_are_rejected() {
    let mut checkout = checkout();
    checkout.bodies = 2;
    assert!(matches!(
        checkout.encode_meta(),
        Err(ProtoError::ValueOutOfRange {
            tag: super::tag::BODIES,
            ..
        })
    ));

    let mut read = file_read();
    read.range_len = MAX_RANGE + 1;
    assert!(matches!(
        read.encode_meta(),
        Err(ProtoError::ValueOutOfRange {
            tag: super::tag::RANGE_LEN,
            ..
        })
    ));

    let mut data = file_data();
    data.range_len = MAX_RANGE + 1;
    assert!(matches!(
        data.encode_meta(),
        Err(ProtoError::ValueOutOfRange {
            tag: super::tag::RANGE_LEN,
            ..
        })
    ));

    let mut request = signature_request();
    request.files[0].size = Limits::new().max_file_size + 1;
    assert!(matches!(
        request.encode_meta(),
        Err(ProtoError::ValueOutOfRange {
            tag: super::tag::SIZE,
            ..
        })
    ));
}

#[test]
fn paths_and_names_are_canonical() {
    assert!(check_path("/").is_ok());
    assert!(check_path("/a/b").is_ok());
    for bad in ["", "a", "//a", "/a/", "/a//b", "/a/./b", "/a/../b", "/a\0b"] {
        assert!(check_path(bad).is_err(), "{bad:?} must be rejected");
    }
    let long = format!("/{}", "x".repeat(MAX_PATH));
    assert!(check_path(&long).is_err());

    assert!(check_name("a.txt").is_ok());
    for bad in ["", ".", "..", "a/b", "\0"] {
        assert!(check_name(bad).is_err(), "{bad:?} must be rejected");
    }
    assert!(check_name(&"x".repeat(MAX_NAME + 1)).is_err());

    let mut checkout = checkout();
    checkout.dir_path = "/a/../b".to_owned();
    assert!(checkout.encode_meta().is_err());
    let mut read = file_read();
    read.name = "a/b".to_owned();
    assert!(read.encode_meta().is_err());
    let mut begin = upload_begin();
    begin.namespace = "private/mm".to_owned();
    assert!(begin.encode_meta().is_err());
}

#[test]
fn error_status_mapping_covers_the_required_buckets() {
    for (code, status) in [
        (ErrorCode::AuthFailed, 401),
        (ErrorCode::SessionExpired, 401),
        (ErrorCode::BaseChanged, 409),
        (ErrorCode::SignatureStale, 409),
        (ErrorCode::ManifestIncomplete, 409),
        (ErrorCode::LockHeld, 423),
        (ErrorCode::LockLost, 423),
        (ErrorCode::LockExpired, 423),
        (ErrorCode::TooLarge, 413),
        (ErrorCode::TooManyEntries, 413),
        (ErrorCode::TooManyBlocks, 413),
        (ErrorCode::ManifestInvalid, 422),
        (ErrorCode::HashMismatch, 422),
        (ErrorCode::SizeMismatch, 422),
        (ErrorCode::InstructionMismatch, 422),
        (ErrorCode::BadRequest, 400),
        (ErrorCode::PathInvalid, 400),
        (ErrorCode::Internal, 500),
        (ErrorCode::Busy, 503),
        (ErrorCode::NoSpace, 507),
    ] {
        assert_eq!(code.http_status(), status, "{code}");
        assert_eq!(error_body(code).http_status(), status);
    }
}

#[test]
fn error_bodies_enforce_code_specific_fields() {
    assert!(matches!(
        ErrorBody::new(ErrorCode::LockHeld).encode_meta(),
        Err(ProtoError::Inconsistent(_))
    ));
    assert!(matches!(
        ErrorBody::new(ErrorCode::BaseChanged).encode_meta(),
        Err(ProtoError::Inconsistent(_))
    ));
    assert!(matches!(
        ErrorBody::new(ErrorCode::ManifestIncomplete).encode_meta(),
        Err(ProtoError::Inconsistent(_))
    ));
    assert!(matches!(
        ErrorBody::new(ErrorCode::LockLost).encode_meta(),
        Err(ProtoError::Inconsistent(_))
    ));

    let mut body = error_body(ErrorCode::LockHeld);
    body.retry_full = true;
    assert!(matches!(
        body.encode_meta(),
        Err(ProtoError::Inconsistent(_))
    ));

    let mut body = error_body(ErrorCode::ManifestIncomplete);
    body.missing = vec!["a/b".to_owned()];
    assert!(body.encode_meta().is_err());

    let mut body = error_body(ErrorCode::HashMismatch);
    body.retry_full = true;
    body.detail = Some("hash differs".to_owned());
    round_trip(&body);
}

#[test]
fn manifest_requires_structural_completeness() {
    let mut begin = upload_begin();
    begin.structural.clear();
    assert!(matches!(begin.validate(), Err(ProtoError::Inconsistent(_))));

    let mut begin = upload_begin();
    begin
        .structural
        .push(dir_entry(EntryOp::DirAdd).with_name("extra"));
    assert!(matches!(begin.validate(), Err(ProtoError::Inconsistent(_))));

    let mut begin = upload_begin();
    begin.structural[0].op = EntryOp::DirRemove;
    assert!(matches!(begin.validate(), Err(ProtoError::Inconsistent(_))));

    let mut begin = upload_begin();
    begin.structural[0] = file_entry(EntryOp::Keep);
    assert!(matches!(begin.validate(), Err(ProtoError::Inconsistent(_))));

    let mut begin = upload_begin();
    begin.entries.push(file_entry(EntryOp::Put));
    assert!(matches!(begin.validate(), Err(ProtoError::Inconsistent(_))));
}

#[test]
fn entry_rules_reject_contradictions() {
    let mut entry = file_entry(EntryOp::Put);
    entry.content_hash = None;
    assert!(entry.encode_record().is_err());

    let mut entry = file_entry(EntryOp::Keep);
    entry.ino = None;
    assert!(entry.encode_record().is_err());

    let mut entry = dir_entry(EntryOp::DirAdd);
    entry.size = 1;
    assert!(entry.encode_record().is_err());

    let mut entry = dir_entry(EntryOp::DirAdd);
    entry.content_hash = Some(HASH);
    assert!(entry.encode_record().is_err());

    let mut entry = file_entry(EntryOp::Put);
    entry.op = EntryOp::Rename;
    entry.from_name = None;
    assert!(entry.encode_record().is_err());

    let mut entry = file_entry(EntryOp::Put);
    entry.op = EntryOp::Delete;
    entry.content_hash = Some(HASH);
    assert!(entry.encode_record().is_err());

    let mut entry = file_entry(EntryOp::Put);
    entry.kind = EntryKind::Symlink;
    entry.target = None;
    assert!(entry.encode_record().is_err());

    let mut entry = symlink_entry(EntryOp::Put);
    entry.target = None;
    entry.validate_basic().unwrap();
    assert!(entry.validate_manifest().is_err());
}

#[test]
fn snapshot_entries_must_describe_the_current_tree() {
    let mut snap = snapshot();
    let mut dir = dir_entry(EntryOp::Keep);
    dir.file_root = Some([0xAA; 32]);
    snap.entries.push(dir);
    snap.validate().unwrap();

    let mut snap = snapshot();
    snap.entries[0].op = EntryOp::Put;
    assert!(matches!(snap.validate(), Err(ProtoError::Inconsistent(_))));

    let mut snap = snapshot();
    snap.entries[0].file_root = None;
    assert!(snap.validate().is_err());

    let mut snap = snapshot();
    snap.entries[1].target = None;
    assert!(snap.validate().is_err());

    let mut snap = snapshot();
    snap.entries.push(file_entry(EntryOp::Keep));
    assert!(snap.validate().is_err());
}

fn frame_bytes<M: Message>(message: &M, payload: &[u8]) -> Vec<u8> {
    let limits = Limits::new();
    let meta = message.encode_meta().unwrap();
    let mut writer =
        SmmWriter::begin(Vec::new(), M::KIND, &meta, payload.len() as u64, &limits).unwrap();
    writer.write_payload(payload).unwrap();
    writer.finish().unwrap().0
}

#[test]
fn mac_binds_the_streamed_frame_and_rejects_tampering() {
    let keys = SessionKeys::new(
        derive_session_key(&MASTER, &CLIENT_NONCE, &SERVER_NONCE, &SESSION),
        SESSION,
        u64::MAX,
    );
    let bytes = frame_bytes(&file_data(), b"abc");
    let mut reader = SmmReader::open(Cursor::new(bytes), &Limits::new()).unwrap();
    let mut payload = Vec::new();
    reader.copy_payload(&mut payload).unwrap();
    let digest = reader.finish().unwrap();

    let parts = MacParts {
        method: "POST",
        path: "/private-mm/mm/v1/file/read",
        seq: 1,
        meta_hash: digest.meta_hash,
        payload_hash: digest.payload_hash,
    };
    let mac = keys.mac(&parts).unwrap();
    keys.verify_mac(&parts, &mac).unwrap();

    let tampered_meta = MacParts {
        meta_hash: hash_meta(b"other meta"),
        ..parts
    };
    assert!(matches!(
        keys.verify_mac(&tampered_meta, &mac),
        Err(AuthError::BadMac)
    ));
    let tampered_payload = MacParts {
        payload_hash: hash_payload(b"abd"),
        ..parts
    };
    assert!(matches!(
        keys.verify_mac(&tampered_payload, &mac),
        Err(AuthError::BadMac)
    ));
    let other_path = MacParts {
        path: "/private-mm/mm/v1/checkout",
        ..parts
    };
    assert!(matches!(
        keys.verify_mac(&other_path, &mac),
        Err(AuthError::BadMac)
    ));
}

#[test]
fn mac_replay_and_session_expiry_are_rejected() {
    let keys = SessionKeys::new(
        derive_session_key(&MASTER, &CLIENT_NONCE, &SERVER_NONCE, &SESSION),
        SESSION,
        u64::MAX,
    );
    let parts = MacParts {
        method: "POST",
        path: "/private-mm/mm/v1/upload/commit",
        seq: 9,
        meta_hash: hash_meta(b"m"),
        payload_hash: hash_payload(b"p"),
    };
    let mac = keys.mac(&parts).unwrap();

    let mut guard = SessionGuard::new(1_000);
    guard.verify(&keys, &parts, &mac, 999).unwrap();
    assert!(matches!(
        guard.verify(&keys, &parts, &mac, 999),
        Err(ProtoError::Auth(AuthError::SeqReplay {
            seq: 9,
            last_seq: 9
        }))
    ));

    let mut guard = SessionGuard::new(1_000);
    assert!(matches!(
        guard.verify(&keys, &parts, &mac, 1_001),
        Err(ProtoError::Auth(AuthError::SessionExpired { .. }))
    ));

    let wrong_seq = MacParts { seq: 10, ..parts };
    let mut guard = SessionGuard::new(u64::MAX);
    assert!(matches!(
        guard.verify(&keys, &wrong_seq, &mac, 0),
        Err(ProtoError::Auth(AuthError::BadMac))
    ));
}

#[test]
fn hello_and_welcome_proofs_are_checked_end_to_end() {
    let hello = hello();
    let welcome = welcome();
    let mut guard = crate::protocol::handshake::NonceReplayGuard::new();
    verify_hello(&hello, 1_000_000, &derive_hello_key(&MASTER), &mut guard).unwrap();
    let keys = accept_welcome(&MASTER, &hello, &welcome).unwrap();
    assert_eq!(keys.session_id(), &SESSION);
    assert_eq!(keys.expires_at_ms(), welcome.session_expires_at_ms);
}

#[test]
fn instruction_stream_rides_the_commit_payload() {
    let mut instructions = InstructionWriter::new(Vec::new());
    instructions.literal(0, b"hello").unwrap();
    instructions
        .write(Instruction::Copy {
            file_index: 0,
            block_index: 3,
            strong: STRONG,
        })
        .unwrap();
    instructions
        .write(Instruction::Unchanged {
            file_index: 1,
            content_hash: HASH,
        })
        .unwrap();
    instructions
        .write(Instruction::EndFile { file_index: 0 })
        .unwrap();
    instructions
        .write(Instruction::EndFile { file_index: 1 })
        .unwrap();
    instructions.write(Instruction::EndBatch).unwrap();
    let payload = instructions.finish().unwrap();

    let bytes = frame_bytes(&upload_commit(), &payload);
    let mut reader = SmmReader::open(Cursor::new(bytes), &Limits::new()).unwrap();
    let mut copied = Vec::new();
    reader.copy_payload(&mut copied).unwrap();
    let digest = reader.finish().unwrap();
    assert_eq!(digest.payload_hash, hash_payload(&payload));

    let mut parsed = InstructionReader::new(Cursor::new(copied));
    let first = parsed.next_instruction().unwrap().unwrap();
    assert!(matches!(
        first,
        Instruction::Literal {
            file_index: 0,
            len: 5
        }
    ));
    let mut literal = Vec::new();
    parsed.copy_literal(&mut literal).unwrap();
    assert_eq!(literal, b"hello");
    assert!(matches!(
        parsed.next_instruction().unwrap(),
        Some(Instruction::Copy { block_index: 3, .. })
    ));
    assert!(matches!(
        parsed.next_instruction().unwrap(),
        Some(Instruction::Unchanged { file_index: 1, .. })
    ));
    assert!(matches!(
        parsed.next_instruction().unwrap(),
        Some(Instruction::EndFile { file_index: 0 })
    ));
    assert!(matches!(
        parsed.next_instruction().unwrap(),
        Some(Instruction::EndFile { file_index: 1 })
    ));
    assert!(matches!(
        parsed.next_instruction().unwrap(),
        Some(Instruction::EndBatch)
    ));
    parsed.finish().unwrap();
}

impl Entry {
    fn with_name(mut self, name: &str) -> Self {
        self.name = name.to_owned();
        self
    }
}
