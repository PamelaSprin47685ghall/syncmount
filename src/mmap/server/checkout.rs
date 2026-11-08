//! Checkout, byte-range reads and directory versions.
//!
//! A checkout always runs on one [`crate::mmap::ReadTx`]. The snapshot
//! sequence, the entries and the optional bodies therefore describe exactly
//! one WAL snapshot even if a commit lands while the response is streaming.

use bytes::Bytes;

use crate::mmap::db::{MmTx, ReadTx};
use crate::mmap::proto::ErrorCode;
use crate::mmap::proto::{
    Checkout, DirAttrs as WireDirAttrs, DirVersion, Entry as WireEntry, EntryKind as WireKind,
    EntryOp as WireOp, FileData, FileRead, Snapshot,
};
use crate::mmap::types::EntryKind;
use crate::mmap::types::FileRecord;
use crate::transport::BODY_QUEUE_DEPTH;
use crate::transport::body::MpscBody;

use super::http::{self, Response, encode_head, stream_response};
use super::{Fault, ServerState};

impl ServerState {
    /// `CHECKOUT`: manifest, optional bodies, or 304.
    pub async fn checkout(&self, request: Checkout) -> Result<Response, Fault> {
        self.check_wire_namespace(&request.namespace)?;
        let tx = self.read()?;
        let Some(dir) = tx.dir_by_path(&request.dir_path)? else {
            return Err(Fault::detail(
                ErrorCode::DirNotFound,
                format!("directory {} does not exist", request.dir_path),
            ));
        };
        let snapshot_seq = tx.mm_seq()?;
        if request.if_dir_version == Some(dir.base.dir_version)
            || request.if_snapshot_seq == Some(snapshot_seq.get())
        {
            return Ok(http::not_modified(&[
                ("x-sm-mm-epoch", dir.base.epoch.to_string()),
                ("x-sm-mm-snapshot-seq", snapshot_seq.get().to_string()),
                ("x-sm-mm-base-seq", dir.base.dir_seq.get().to_string()),
                ("x-sm-mm-dir-version", hex::encode(dir.base.dir_version)),
            ]));
        }

        let records = tx.files(dir.ino)?;
        let entries: Vec<WireEntry> = records
            .iter()
            .map(snapshot_entry)
            .collect::<Result<_, _>>()?;
        let dir_attrs = WireDirAttrs {
            mode: dir.attrs.mode,
            uid: dir.attrs.uid,
            gid: dir.attrs.gid,
            mtime_ns: u64::try_from(dir.attrs.mtime_ns)
                .map_err(|_| Fault::detail(ErrorCode::Internal, "directory mtime is negative"))?,
        };
        let snapshot = Snapshot {
            snapshot_seq: snapshot_seq.get(),
            epoch: dir.base.epoch,
            base_seq: dir.base.dir_seq.get(),
            dir_ino: dir.ino,
            dir_path: dir.path.clone(),
            dir_version: dir.base.dir_version,
            dir_attrs,
            entries,
        };
        if request.bodies == 0 {
            return http::bytes_response(&snapshot, &[]);
        }

        let mut files = Vec::new();
        let mut data_len = 0u64;
        for record in &records {
            if record.kind != EntryKind::File {
                continue;
            }
            let chunks = tx.version_chunks(record.ino, record.version)?;
            let chunk_total: u64 = chunks.iter().map(|chunk| u64::from(chunk.len)).sum();
            if chunk_total != record.size {
                return Err(Fault::detail(
                    ErrorCode::Internal,
                    format!("{} has an inconsistent chunk list", record.name),
                ));
            }
            data_len = data_len.saturating_add(record.size);
            files.push((record.clone(), chunks));
        }
        if data_len > self.config().limits.max_data_len {
            return Err(Fault::detail(
                ErrorCode::TooLarge,
                "checkout bodies exceed the batch limit",
            ));
        }
        let (header, meta) = encode_head(&snapshot, data_len, &self.config().limits)?;

        let (sender, body) = MpscBody::channel(BODY_QUEUE_DEPTH);
        tokio::spawn(async move {
            let mut sender = sender;
            let mut head = Vec::with_capacity(24 + meta.len());
            head.extend_from_slice(&header.encode());
            head.extend_from_slice(&meta);
            if sender.send(Bytes::from(head)).await.is_err() {
                return;
            }
            for (record, chunks) in files {
                let mut sent = 0u64;
                for chunk in chunks {
                    let Ok(Some(data)) = tx.chunk(chunk.hash) else {
                        sender.close();
                        return;
                    };
                    if data.len() != chunk.len as usize {
                        sender.close();
                        return;
                    }
                    if sender.send(Bytes::from(data)).await.is_err() {
                        return;
                    }
                    sent = sent.saturating_add(u64::from(chunk.len));
                }
                if sent != record.size {
                    sender.close();
                    return;
                }
            }
            sender.close();
        });
        Ok(stream_response(200, body))
    }

    /// `FILE_READ`: one verified byte range.
    pub fn file_read(&self, request: FileRead) -> Result<Response, Fault> {
        self.check_wire_namespace(&request.namespace)?;
        let tx = self.read()?;
        let Some(dir) = tx.dir_by_path(&request.dir_path)? else {
            return Err(Fault::detail(
                ErrorCode::DirNotFound,
                format!("directory {} does not exist", request.dir_path),
            ));
        };
        let Some(record) = tx.file_by_name(dir.ino, &request.name)? else {
            return Err(Fault::detail(
                ErrorCode::FileChanged,
                "file is no longer present",
            ));
        };
        if record.kind != EntryKind::File
            || record.ino != request.ino
            || record.file_root != request.file_root
        {
            return Err(Fault::detail(
                ErrorCode::FileChanged,
                "file identity changed since checkout",
            ));
        }
        let start = request.range_offset.min(record.size);
        let len = (u64::from(request.range_len)).min(record.size - start);
        let bytes = read_range(&tx, &record, start, len)?;
        let data = FileData {
            range_offset: start,
            range_len: u32::try_from(bytes.len())
                .map_err(|_| Fault::detail(ErrorCode::Internal, "range does not fit u32"))?,
            range_hash: *blake3::hash(&bytes).as_bytes(),
        };
        http::bytes_response(&data, &bytes)
    }

    /// `GET version?dir_ino=...`.
    pub fn dir_version(&self, dir_ino: [u8; 16]) -> Result<Response, Fault> {
        let tx = self.read()?;
        let Some(record) = tx.dir_version_record(dir_ino)? else {
            return Err(Fault::detail(ErrorCode::DirNotFound, "directory not found"));
        };
        let snapshot_seq = tx.mm_seq()?;
        let message = DirVersion {
            epoch: record.base_epoch,
            snapshot_seq: snapshot_seq.get(),
            base_seq: record.dir_seq.get(),
            dir_version: record.dir_version,
            dir_ino: record.dir_ino,
            dir_path: record.dir_path,
        };
        http::message_response(&message)
    }
}

pub(crate) fn snapshot_entry(record: &FileRecord) -> Result<WireEntry, Fault> {
    let mtime_ns = u64::try_from(record.attrs.mtime_ns)
        .map_err(|_| Fault::detail(ErrorCode::Internal, "entry mtime is negative"))?;
    Ok(WireEntry {
        name: record.name.clone(),
        ino: Some(record.ino),
        kind: match record.kind {
            EntryKind::File => WireKind::File,
            EntryKind::Symlink => WireKind::Symlink,
            EntryKind::Dir => WireKind::Dir,
        },
        op: WireOp::Keep,
        from_name: None,
        mode: record.attrs.mode,
        uid: record.attrs.uid,
        gid: record.attrs.gid,
        mtime_ns,
        size: record.size,
        file_root: Some(record.file_root),
        content_hash: if record.kind == EntryKind::File {
            record.content_hash
        } else {
            None
        },
        target: record.target.clone(),
    })
}

/// Read exactly `len` bytes at `offset` from the current version of a file.
pub(crate) fn read_range(
    tx: &ReadTx,
    record: &FileRecord,
    offset: u64,
    len: u64,
) -> Result<Vec<u8>, Fault> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let end = offset
        .checked_add(len)
        .ok_or_else(|| Fault::detail(ErrorCode::Internal, "range overflows"))?;
    let chunks = tx.version_chunks(record.ino, record.version)?;
    let mut out = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    for chunk in chunks {
        let chunk_end = chunk.offset.saturating_add(u64::from(chunk.len));
        if chunk_end <= offset {
            continue;
        }
        if chunk.offset >= end {
            break;
        }
        let data = tx.chunk(chunk.hash)?.ok_or_else(|| {
            Fault::detail(
                ErrorCode::Internal,
                format!("content chunk {} is missing", hex::encode(chunk.hash)),
            )
        })?;
        let slice_start = usize::try_from(offset.saturating_sub(chunk.offset)).unwrap_or(0);
        let slice_end = usize::try_from(end.min(chunk_end) - chunk.offset).unwrap_or(0);
        if slice_start >= data.len() || slice_end > data.len() || slice_start > slice_end {
            return Err(Fault::detail(
                ErrorCode::Internal,
                "chunk range is outside the stored bytes",
            ));
        }
        out.extend_from_slice(&data[slice_start..slice_end]);
    }
    if out.len() as u64 != len {
        return Err(Fault::detail(
            ErrorCode::Internal,
            "stored chunks do not cover the requested range",
        ));
    }
    Ok(out)
}
