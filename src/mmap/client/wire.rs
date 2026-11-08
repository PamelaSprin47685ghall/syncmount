//! Wire conversion and the multi-file commit instruction plan.
//!
//! The shadow builds one `UploadFile` per manifest file and may end each
//! file's instruction list with its own `END_BATCH`. The SMM1 stream has one
//! `END_BATCH` for the whole batch, and every instruction names a manifest
//! index. [`CommitPlan`] performs that remapping once, then hashes and streams
//! the same bytes.

use std::io::Write;

use crate::mmap::proto::{Entry, Instruction, InstructionWriter};
use crate::mmap::shadow::{RemoteError, UploadCommit, UploadFile};
use crate::mmap::types::{DirAttrs, EntryKind, EntryOp, Hash, ManifestEntry};

/// Convert one typed manifest entry to its wire form.
///
/// A deleted regular file must not carry `file_root` or `content_hash`: the
/// wire validator rejects content on a `DELETE`, and the server hashes the
/// entry it actually received. The other operations keep the conversion in
/// `proto::convert`.
pub(super) fn wire_entry(entry: &ManifestEntry) -> Result<Entry, RemoteError> {
    if entry.op == EntryOp::Delete && entry.kind != EntryKind::Dir {
        let kind = match entry.kind {
            EntryKind::File => crate::mmap::proto::EntryKind::File,
            EntryKind::Symlink => crate::mmap::proto::EntryKind::Symlink,
            EntryKind::Dir => {
                return Err(RemoteError::Internal(
                    "directories use DIR_REMOVE".to_owned(),
                ));
            }
        };
        // A deleted symlink still needs its target on the wire: the server
        // derives the inode's canonical root from it before dropping the
        // entry. A deleted regular file carries no content.
        let (size, target) = if kind == crate::mmap::proto::EntryKind::Symlink {
            let target = entry.target.clone().ok_or_else(|| {
                RemoteError::Internal(format!("deleted symlink {} has no target", entry.name))
            })?;
            (target.len() as u64, Some(target))
        } else {
            (0, None)
        };
        return Ok(Entry {
            name: entry.name.clone(),
            ino: Some(entry.ino),
            kind,
            op: crate::mmap::proto::EntryOp::Delete,
            from_name: None,
            mode: entry.mode,
            uid: entry.uid,
            gid: entry.gid,
            mtime_ns: u64::try_from(entry.mtime_ns).map_err(|_| {
                RemoteError::Internal(format!(
                    "manifest entry {} has a negative mtime",
                    entry.name
                ))
            })?,
            size,
            file_root: None,
            content_hash: None,
            target,
        });
    }
    Entry::try_from(entry)
        .map_err(|error| RemoteError::Internal(format!("manifest entry {}: {error}", entry.name)))
}

/// The order the server stores a begin manifest in.
///
/// `assign_entries` sorts by name bytes, and commit instructions index into
/// that sorted list. The client canonicalizes before encoding so an unsorted
/// caller cannot shift every later file index.
pub(super) fn sorted_indices(entries: &[ManifestEntry]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..entries.len()).collect();
    order.sort_by(|left, right| {
        entries[*left]
            .name
            .as_bytes()
            .cmp(entries[*right].name.as_bytes())
    });
    order
}

/// The begin/commit idempotency hash over typed entries.
pub(super) fn manifest_hash(entries: &[ManifestEntry]) -> Result<Hash, RemoteError> {
    let order = sorted_indices(entries);
    let wire = order
        .iter()
        .map(|index| wire_entry(&entries[*index]))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(wire_hash(&wire))
}

/// `BLAKE3` over the canonical manifest bytes of wire entries.
///
/// This mirrors the server's `wire_manifest_hash`: missing file roots take
/// the kind's canonical default, so a deleted file hashes the same bytes on
/// both ends even though it carries no root.
pub(super) fn wire_hash(entries: &[Entry]) -> Hash {
    let mut sorted: Vec<&Entry> = entries.iter().collect();
    sorted.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(u32::try_from(sorted.len()).unwrap_or(u32::MAX)).to_le_bytes());
    for entry in sorted {
        feed_bytes(&mut hasher, entry.name.as_bytes());
        hasher.update(&[entry.kind.as_u8()]);
        hasher.update(&[entry.op.as_u8()]);
        match &entry.from_name {
            Some(name) => {
                hasher.update(&[1]);
                feed_bytes(&mut hasher, name.as_bytes());
            }
            None => {
                hasher.update(&[0]);
            }
        }
        hasher.update(&entry.ino.unwrap_or([0u8; 16]));
        hasher.update(&entry.mode.to_le_bytes());
        hasher.update(&entry.uid.to_le_bytes());
        hasher.update(&entry.gid.to_le_bytes());
        hasher.update(&entry.mtime_ns.to_le_bytes());
        hasher.update(&entry.size.to_le_bytes());
        let root = entry.file_root.unwrap_or_else(|| match entry.kind {
            crate::mmap::proto::EntryKind::Dir => crate::mmap::base::dir_root(),
            crate::mmap::proto::EntryKind::Symlink => entry
                .target
                .as_deref()
                .map(crate::mmap::base::symlink_root)
                .unwrap_or([0u8; 32]),
            crate::mmap::proto::EntryKind::File => [0u8; 32],
        });
        hasher.update(&root);
        match &entry.content_hash {
            Some(hash) => {
                hasher.update(&[1]);
                hasher.update(hash);
            }
            None => {
                hasher.update(&[0]);
            }
        }
        match &entry.target {
            Some(target) => {
                hasher.update(&[1]);
                feed_bytes(&mut hasher, target);
            }
            None => {
                hasher.update(&[0]);
            }
        }
    }
    *hasher.finalize().as_bytes()
}

fn feed_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(u32::try_from(bytes.len()).unwrap_or(u32::MAX)).to_le_bytes());
    hasher.update(bytes);
}

/// Convert directory attributes to the wire form.
pub(super) fn wire_attrs(attrs: &DirAttrs) -> Result<crate::mmap::proto::DirAttrs, RemoteError> {
    crate::mmap::proto::DirAttrs::try_from(attrs)
        .map_err(|error| RemoteError::Internal(format!("directory attributes: {error}")))
}

/// One encoded instruction, with a borrowed literal body.
enum Step<'a> {
    Copy {
        file_index: u32,
        block_index: u32,
        strong: [u8; 16],
    },
    Literal {
        file_index: u32,
        bytes: &'a [u8],
    },
    Unchanged {
        file_index: u32,
        content_hash: [u8; 32],
    },
    EndFile {
        file_index: u32,
    },
    EndBatch,
}

impl Step<'_> {
    fn instruction(&self) -> Result<Instruction, RemoteError> {
        Ok(match self {
            Self::Copy {
                file_index,
                block_index,
                strong,
            } => Instruction::Copy {
                file_index: *file_index,
                block_index: *block_index,
                strong: *strong,
            },
            Self::Literal { file_index, bytes } => Instruction::Literal {
                file_index: *file_index,
                len: u32::try_from(bytes.len())
                    .map_err(|_| RemoteError::Internal("literal does not fit u32".to_owned()))?,
            },
            Self::Unchanged {
                file_index,
                content_hash,
            } => Instruction::Unchanged {
                file_index: *file_index,
                content_hash: *content_hash,
            },
            Self::EndFile { file_index } => Instruction::EndFile {
                file_index: *file_index,
            },
            Self::EndBatch => Instruction::EndBatch,
        })
    }
}

/// A complete instruction stream plus its length and BLAKE3 hash.
pub(super) struct CommitPlan<'a> {
    steps: Vec<Step<'a>>,
    pub data_len: u64,
    pub payload_hash: [u8; 32],
}

impl<'a> CommitPlan<'a> {
    /// Remap every file group and emit one terminal `END_BATCH`.
    pub fn build(commit: &'a UploadCommit) -> Result<Self, RemoteError> {
        let mut by_index = std::collections::HashMap::new();
        for file in &commit.files {
            if by_index.insert(file.manifest_index, file).is_some() {
                return Err(RemoteError::Internal(format!(
                    "duplicate upload file index {}",
                    file.manifest_index
                )));
            }
        }

        let order = sorted_indices(&commit.manifest);
        let mut steps = Vec::new();
        for (sorted_index, original_index) in order.iter().enumerate() {
            let index = u32::try_from(sorted_index)
                .map_err(|_| RemoteError::Internal("manifest index does not fit u32".to_owned()))?;
            let original_index = u32::try_from(*original_index)
                .map_err(|_| RemoteError::Internal("manifest index does not fit u32".to_owned()))?;
            let entry = &commit.manifest[original_index as usize];
            if entry.kind != EntryKind::File || entry.op == EntryOp::Delete {
                continue;
            }
            if entry.op == EntryOp::Keep || entry.op == EntryOp::Rename {
                let content_hash = content_hash_for(entry, by_index.get(&original_index).copied())?;
                steps.push(Step::Unchanged {
                    file_index: index,
                    content_hash,
                });
                steps.push(Step::EndFile { file_index: index });
                continue;
            }
            let Some(file) = by_index.get(&original_index).copied() else {
                return Err(RemoteError::Internal(format!(
                    "manifest file {} has no upload file",
                    entry.name
                )));
            };
            if file.unchanged {
                steps.push(Step::Unchanged {
                    file_index: index,
                    content_hash: file.content_hash,
                });
                steps.push(Step::EndFile { file_index: index });
                continue;
            }
            let mut ended = false;
            for instruction in &file.instructions {
                match instruction {
                    crate::mmap::rsync::Instruction::Literal { bytes, .. } => {
                        steps.push(Step::Literal {
                            file_index: index,
                            bytes,
                        });
                    }
                    crate::mmap::rsync::Instruction::Copy { block, strong, .. } => {
                        steps.push(Step::Copy {
                            file_index: index,
                            block_index: *block,
                            strong: *strong,
                        });
                    }
                    crate::mmap::rsync::Instruction::Unchanged { content_hash, .. } => {
                        steps.push(Step::Unchanged {
                            file_index: index,
                            content_hash: *content_hash,
                        });
                    }
                    crate::mmap::rsync::Instruction::EndFile { .. } => {
                        if !ended {
                            steps.push(Step::EndFile { file_index: index });
                            ended = true;
                        }
                    }
                    crate::mmap::rsync::Instruction::EndBatch => {}
                }
            }
            if !ended {
                steps.push(Step::EndFile { file_index: index });
            }
        }
        steps.push(Step::EndBatch);

        let mut hasher = HashSink::default();
        {
            let mut writer = InstructionWriter::new(&mut hasher);
            for step in &steps {
                writer
                    .write(step.instruction()?)
                    .map_err(|error| RemoteError::Internal(error.to_string()))?;
                if let Step::Literal { bytes, .. } = step {
                    writer
                        .write_literal(bytes)
                        .map_err(|error| RemoteError::Internal(error.to_string()))?;
                }
            }
            writer
                .finish()
                .map_err(|error| RemoteError::Internal(error.to_string()))?;
        }
        Ok(Self {
            steps,
            data_len: hasher.len,
            payload_hash: *hasher.hasher.finalize().as_bytes(),
        })
    }

    /// Stream the plan into one sink.
    pub fn write_to(&self, sink: impl Write) -> std::io::Result<()> {
        let mut writer = InstructionWriter::new(sink);
        for step in &self.steps {
            writer
                .write(step.instruction().map_err(std::io::Error::other)?)
                .map_err(std::io::Error::other)?;
            if let Step::Literal { bytes, .. } = step {
                writer.write_literal(bytes).map_err(std::io::Error::other)?;
            }
        }
        writer.finish().map_err(std::io::Error::other)?;
        Ok(())
    }
}

#[derive(Default)]
struct HashSink {
    hasher: blake3::Hasher,
    len: u64,
}

impl Write for HashSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(bytes);
        self.len = self
            .len
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| std::io::Error::other("instruction stream overflows"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn content_hash_for(
    entry: &ManifestEntry,
    file: Option<&UploadFile>,
) -> Result<[u8; 32], RemoteError> {
    if let Some(file) = file {
        return Ok(file.content_hash);
    }
    if let Some(hash) = entry.content_hash {
        return Ok(hash);
    }
    if entry.kind == EntryKind::Symlink {
        let target = entry.target.as_deref().ok_or_else(|| {
            RemoteError::Internal(format!("symlink {} has no target", entry.name))
        })?;
        return Ok(*blake3::hash(target).as_bytes());
    }
    Err(RemoteError::Internal(format!(
        "unchanged file {} has no content hash",
        entry.name
    )))
}
