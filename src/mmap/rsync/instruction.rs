//! COPY / LITERAL / UNCHANGED instruction stream.
//!
//! Wire layout:
//!
//! ```text
//! magic [4] = "SMD1" | version u8 | flags u8 | reserved u16
//! 0x01 LITERAL:   file u32 | len u32 | bytes[len]
//! 0x02 COPY:      file u32 | block u32 | offset u64 | len u32 | strong[16]
//! 0x03 UNCHANGED: file u32 | content_hash[32]
//! 0x04 END_FILE:  file u32
//! 0x05 END_BATCH
//! ```
//!
//! All integers are big-endian. COPY carries the resolved base range
//! (`offset`, `len`) as well as the signature block index and its BLAKE3-128.
//! That lets [`super::apply`] verify the base bytes without a second
//! signature lookup.
//!
//! # Protocol mapping
//!
//! The SMM1 `UPLOAD_COMMIT` stream carries only `(file_index, block_index,
//! strong)` for COPY. The server maps it to this type with
//! `offset = block_index * block_size` and
//! `len = signature.blocks[block_index].block_len`. The strong hash is the
//! same BLAKE3-128 value. LITERAL, UNCHANGED, END_FILE and END_BATCH map
//! directly.

use std::collections::BTreeSet;
use std::io::{self, Read, Write};

use super::engine::{LITERAL_CHUNK_BYTES, RsyncError};
use super::strong::{Hash256, StrongHash};

/// Instruction stream magic.
pub const INSTRUCTION_MAGIC: [u8; 4] = *b"SMD1";
/// Instruction stream version.
pub const INSTRUCTION_VERSION: u8 = 1;
/// Header size.
pub const INSTRUCTION_HEADER_BYTES: usize = 8;

const TAG_LITERAL: u8 = 0x01;
const TAG_COPY: u8 = 0x02;
const TAG_UNCHANGED: u8 = 0x03;
const TAG_END_FILE: u8 = 0x04;
const TAG_END_BATCH: u8 = 0x05;

/// One delta instruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Instruction {
    /// Literal bytes that are not in the base.
    Literal {
        /// Manifest file index.
        file: u32,
        /// Literal payload.
        bytes: Vec<u8>,
    },
    /// Copy a range from the base.
    Copy {
        /// Manifest file index.
        file: u32,
        /// Signature block index that produced the match.
        block: u32,
        /// Base byte offset.
        offset: u64,
        /// Base byte length.
        len: u32,
        /// BLAKE3-128 of the base range.
        strong: StrongHash,
    },
    /// The whole file is unchanged.
    Unchanged {
        /// Manifest file index.
        file: u32,
        /// BLAKE3-256 of the whole file.
        content_hash: Hash256,
    },
    /// End of one file's instructions.
    EndFile {
        /// Manifest file index.
        file: u32,
    },
    /// End of the batch.
    EndBatch,
}

impl Instruction {
    /// File index carried by the instruction, or `None` for END_BATCH.
    #[must_use]
    pub fn file(&self) -> Option<u32> {
        match self {
            Self::Literal { file, .. }
            | Self::Copy { file, .. }
            | Self::Unchanged { file, .. }
            | Self::EndFile { file } => Some(*file),
            Self::EndBatch => None,
        }
    }

    /// Encoded size in bytes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::Literal { bytes, .. } => 1 + 4 + 4 + bytes.len(),
            Self::Copy { .. } => 1 + 4 + 4 + 8 + 4 + 16,
            Self::Unchanged { .. } => 1 + 4 + 32,
            Self::EndFile { .. } => 1 + 4,
            Self::EndBatch => 1,
        }
    }

    /// Write one record, without the stream header.
    pub fn encode_record<W: Write>(&self, out: &mut W) -> Result<(), RsyncError> {
        match self {
            Self::Literal { file, bytes } => write_literal(out, *file, bytes),
            Self::Copy {
                file,
                block,
                offset,
                len,
                strong,
            } => write_copy(out, *file, *block, *offset, *len, strong),
            Self::Unchanged { file, content_hash } => write_unchanged(out, *file, content_hash),
            Self::EndFile { file } => write_end_file(out, *file),
            Self::EndBatch => write_end_batch(out),
        }
    }
}

/// Encode a complete instruction stream. The list must end with END_BATCH.
pub fn encode_to<W: Write>(instructions: &[Instruction], out: &mut W) -> Result<(), RsyncError> {
    if !matches!(instructions.last(), Some(Instruction::EndBatch)) {
        return Err(RsyncError::BadInstruction(
            "instruction stream must end with END_BATCH",
        ));
    }
    write_header(out)?;
    for instruction in instructions {
        instruction.encode_record(out)?;
    }
    Ok(())
}

/// Decode exactly one instruction stream.
pub fn decode_from<R: Read>(mut reader: R) -> Result<Vec<Instruction>, RsyncError> {
    let mut header = [0u8; INSTRUCTION_HEADER_BYTES];
    read_exact(&mut reader, &mut header)?;
    if header[..4] != INSTRUCTION_MAGIC {
        return Err(RsyncError::BadInstruction("not an instruction stream"));
    }
    if header[4] != INSTRUCTION_VERSION {
        return Err(RsyncError::BadInstruction(
            "unsupported instruction version",
        ));
    }
    if header[5] != 0 || header[6] != 0 || header[7] != 0 {
        return Err(RsyncError::BadInstruction("unsupported instruction flags"));
    }

    let mut instructions = Vec::new();
    let mut open = BTreeSet::new();
    let mut closed = BTreeSet::new();
    let mut ended = false;
    loop {
        let Some(tag) = read_tag(&mut reader)? else {
            break;
        };
        if ended {
            return Err(RsyncError::BadInstruction("record after END_BATCH"));
        }
        match tag {
            TAG_LITERAL => {
                let file = read_u32(&mut reader)?;
                let len = read_u32(&mut reader)?;
                if len as usize > LITERAL_CHUNK_BYTES {
                    return Err(RsyncError::BadInstruction("literal exceeds 64 KiB"));
                }
                let mut bytes = vec![0u8; len as usize];
                read_exact(&mut reader, &mut bytes)?;
                check_open(file, &mut open, &closed)?;
                instructions.push(Instruction::Literal { file, bytes });
            }
            TAG_COPY => {
                let file = read_u32(&mut reader)?;
                let block = read_u32(&mut reader)?;
                let offset = read_u64(&mut reader)?;
                let len = read_u32(&mut reader)?;
                if len == 0 {
                    return Err(RsyncError::BadInstruction("zero-length copy"));
                }
                offset
                    .checked_add(u64::from(len))
                    .ok_or(RsyncError::BadInstruction("copy range overflow"))?;
                let mut strong = [0u8; 16];
                read_exact(&mut reader, &mut strong)?;
                check_open(file, &mut open, &closed)?;
                instructions.push(Instruction::Copy {
                    file,
                    block,
                    offset,
                    len,
                    strong,
                });
            }
            TAG_UNCHANGED => {
                let file = read_u32(&mut reader)?;
                let mut content_hash = [0u8; 32];
                read_exact(&mut reader, &mut content_hash)?;
                check_open(file, &mut open, &closed)?;
                instructions.push(Instruction::Unchanged { file, content_hash });
            }
            TAG_END_FILE => {
                let file = read_u32(&mut reader)?;
                if closed.contains(&file) {
                    return Err(RsyncError::BadInstruction("duplicate END_FILE"));
                }
                open.remove(&file);
                closed.insert(file);
                instructions.push(Instruction::EndFile { file });
            }
            TAG_END_BATCH => {
                if !open.is_empty() {
                    return Err(RsyncError::BadInstruction("file group is missing END_FILE"));
                }
                instructions.push(Instruction::EndBatch);
                ended = true;
            }
            _ => {
                return Err(RsyncError::BadInstruction("unknown instruction tag"));
            }
        }
    }
    if !ended {
        return Err(RsyncError::BadInstruction("missing END_BATCH"));
    }
    if read_tag(&mut reader)?.is_some() {
        return Err(RsyncError::BadInstruction("trailing bytes after END_BATCH"));
    }
    Ok(instructions)
}

fn check_open(
    file: u32,
    open: &mut BTreeSet<u32>,
    closed: &BTreeSet<u32>,
) -> Result<(), RsyncError> {
    if closed.contains(&file) {
        return Err(RsyncError::BadInstruction(
            "record after END_FILE for the same file",
        ));
    }
    open.insert(file);
    Ok(())
}

pub(crate) fn write_header<W: Write>(out: &mut W) -> Result<(), RsyncError> {
    out.write_all(&INSTRUCTION_MAGIC)?;
    out.write_all(&[INSTRUCTION_VERSION, 0, 0, 0])?;
    Ok(())
}

pub(crate) fn write_literal<W: Write>(
    out: &mut W,
    file: u32,
    bytes: &[u8],
) -> Result<(), RsyncError> {
    if bytes.len() > LITERAL_CHUNK_BYTES {
        return Err(RsyncError::BadInstruction("literal exceeds 64 KiB"));
    }
    out.write_all(&[TAG_LITERAL])?;
    out.write_all(&file.to_be_bytes())?;
    out.write_all(&(bytes.len() as u32).to_be_bytes())?;
    out.write_all(bytes)?;
    Ok(())
}

pub(crate) fn write_copy<W: Write>(
    out: &mut W,
    file: u32,
    block: u32,
    offset: u64,
    len: u32,
    strong: &StrongHash,
) -> Result<(), RsyncError> {
    if len == 0 {
        return Err(RsyncError::BadInstruction("zero-length copy"));
    }
    offset
        .checked_add(u64::from(len))
        .ok_or(RsyncError::BadInstruction("copy range overflow"))?;
    out.write_all(&[TAG_COPY])?;
    out.write_all(&file.to_be_bytes())?;
    out.write_all(&block.to_be_bytes())?;
    out.write_all(&offset.to_be_bytes())?;
    out.write_all(&len.to_be_bytes())?;
    out.write_all(strong)?;
    Ok(())
}

pub(crate) fn write_unchanged<W: Write>(
    out: &mut W,
    file: u32,
    content_hash: &Hash256,
) -> Result<(), RsyncError> {
    out.write_all(&[TAG_UNCHANGED])?;
    out.write_all(&file.to_be_bytes())?;
    out.write_all(content_hash)?;
    Ok(())
}

pub(crate) fn write_end_file<W: Write>(out: &mut W, file: u32) -> Result<(), RsyncError> {
    out.write_all(&[TAG_END_FILE])?;
    out.write_all(&file.to_be_bytes())?;
    Ok(())
}

pub(crate) fn write_end_batch<W: Write>(out: &mut W) -> Result<(), RsyncError> {
    out.write_all(&[TAG_END_BATCH])?;
    Ok(())
}

fn read_tag<R: Read>(reader: &mut R) -> Result<Option<u8>, RsyncError> {
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return Ok(None),
            Ok(_) => return Ok(Some(byte[0])),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(RsyncError::Io(error)),
        }
    }
}

fn read_exact<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<(), RsyncError> {
    match reader.read_exact(buffer) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(RsyncError::BadInstruction("truncated instruction stream"))
        }
        Err(error) => Err(RsyncError::Io(error)),
    }
}

fn read_u32<R: Read>(reader: &mut R) -> Result<u32, RsyncError> {
    let mut bytes = [0u8; 4];
    read_exact(reader, &mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64<R: Read>(reader: &mut R) -> Result<u64, RsyncError> {
    let mut bytes = [0u8; 8];
    read_exact(reader, &mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::io::Cursor;

    fn sample() -> Vec<Instruction> {
        vec![
            Instruction::Literal {
                file: 0,
                bytes: b"hello".to_vec(),
            },
            Instruction::Copy {
                file: 0,
                block: 3,
                offset: 12288,
                len: 1024,
                strong: [0x11; 16],
            },
            Instruction::Unchanged {
                file: 1,
                content_hash: [0x22; 32],
            },
            Instruction::EndFile { file: 0 },
            Instruction::EndFile { file: 1 },
            Instruction::EndBatch,
        ]
    }

    #[test]
    fn u_rsync_instruction_roundtrip_all_variants() {
        let instructions = sample();
        let mut bytes = Vec::new();
        encode_to(&instructions, &mut bytes).unwrap();
        assert_eq!(
            bytes.len(),
            INSTRUCTION_HEADER_BYTES
                + instructions
                    .iter()
                    .map(Instruction::encoded_len)
                    .sum::<usize>()
        );
        let decoded = decode_from(Cursor::new(&bytes)).unwrap();
        assert_eq!(decoded, instructions);
    }

    #[test]
    fn u_rsync_instruction_rejects_bad_header() {
        let mut bytes = Vec::new();
        encode_to(&sample(), &mut bytes).unwrap();

        let mut bad = bytes.clone();
        bad[0] ^= 0xff;
        assert!(matches!(
            decode_from(Cursor::new(&bad)),
            Err(RsyncError::BadInstruction(_))
        ));

        let mut bad = bytes.clone();
        bad[4] = 2;
        assert!(matches!(
            decode_from(Cursor::new(&bad)),
            Err(RsyncError::BadInstruction(_))
        ));

        let mut bad = bytes.clone();
        bad[5] = 1;
        assert!(matches!(
            decode_from(Cursor::new(&bad)),
            Err(RsyncError::BadInstruction(_))
        ));
    }

    #[test]
    fn u_rsync_instruction_rejects_truncated() {
        let mut bytes = Vec::new();
        encode_to(&sample(), &mut bytes).unwrap();
        for cut in [0, 1, 4, 7, 8, 9, 12, bytes.len() - 1] {
            let truncated = &bytes[..cut];
            assert!(decode_from(Cursor::new(truncated)).is_err(), "cut={cut}");
        }
    }

    #[test]
    fn u_rsync_instruction_rejects_trailing_and_missing_end() {
        let mut bytes = Vec::new();
        encode_to(&sample(), &mut bytes).unwrap();

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            decode_from(Cursor::new(&trailing)),
            Err(RsyncError::BadInstruction(_))
        ));

        let mut missing = bytes.clone();
        missing.pop();
        assert!(matches!(
            decode_from(Cursor::new(&missing)),
            Err(RsyncError::BadInstruction(_))
        ));

        let empty: Vec<Instruction> = Vec::new();
        let mut out = Vec::new();
        assert!(encode_to(&empty, &mut out).is_err());
    }

    #[test]
    fn u_rsync_instruction_rejects_grouping_errors() {
        let instructions = vec![
            Instruction::Literal {
                file: 0,
                bytes: vec![1],
            },
            Instruction::EndFile { file: 0 },
            Instruction::Literal {
                file: 0,
                bytes: vec![2],
            },
            Instruction::EndBatch,
        ];
        let mut bytes = Vec::new();
        // encode_to does not enforce grouping; the decoder does.
        write_header(&mut bytes).unwrap();
        for instruction in &instructions {
            instruction.encode_record(&mut bytes).unwrap();
        }
        assert!(matches!(
            decode_from(Cursor::new(&bytes)),
            Err(RsyncError::BadInstruction(_))
        ));

        let instructions = vec![
            Instruction::Literal {
                file: 0,
                bytes: vec![1],
            },
            Instruction::EndBatch,
        ];
        let mut bytes = Vec::new();
        write_header(&mut bytes).unwrap();
        for instruction in &instructions {
            instruction.encode_record(&mut bytes).unwrap();
        }
        assert!(matches!(
            decode_from(Cursor::new(&bytes)),
            Err(RsyncError::BadInstruction(_))
        ));
    }

    #[test]
    fn u_rsync_instruction_rejects_bad_payloads() {
        let oversized = Instruction::Literal {
            file: 0,
            bytes: vec![0u8; LITERAL_CHUNK_BYTES + 1],
        };
        let mut out = Vec::new();
        assert!(matches!(
            oversized.encode_record(&mut out),
            Err(RsyncError::BadInstruction(_))
        ));

        let zero_copy = Instruction::Copy {
            file: 0,
            block: 0,
            offset: 0,
            len: 0,
            strong: [0u8; 16],
        };
        let mut out = Vec::new();
        assert!(matches!(
            zero_copy.encode_record(&mut out),
            Err(RsyncError::BadInstruction(_))
        ));

        let mut bytes = Vec::new();
        write_header(&mut bytes).unwrap();
        bytes.push(TAG_LITERAL);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&((LITERAL_CHUNK_BYTES as u32 + 1).to_be_bytes()));
        assert!(matches!(
            decode_from(Cursor::new(&bytes)),
            Err(RsyncError::BadInstruction(_))
        ));
    }

    #[test]
    fn u_rsync_instruction_encoded_len_matches_records() {
        for instruction in sample() {
            let mut bytes = Vec::new();
            instruction.encode_record(&mut bytes).unwrap();
            assert_eq!(bytes.len(), instruction.encoded_len());
        }
    }
}
