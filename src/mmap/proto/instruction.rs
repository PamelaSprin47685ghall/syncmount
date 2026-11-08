//! The `UPLOAD_COMMIT` instruction stream.
//!
//! The stream is the commit payload, not a field stream:
//!
//! ```text
//! COPY       0x01 | file_index u32 | block_index u32 | strong 16
//! LITERAL    0x02 | file_index u32 | len u32 | bytes[len]
//! UNCHANGED  0x03 | file_index u32 | content_hash 32
//! END_FILE   0x04 | file_index u32
//! END_BATCH  0x05
//! ```
//!
//! All integers are little-endian. A `LITERAL` header is followed by exactly
//! `len` raw bytes, which the caller streams through [`InstructionReader`] so
//! a literal never has to fit in memory.

use std::io::{Read, Write};

use super::error::ProtoError;
use super::types::MAX_LITERAL;

/// One commit instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Instruction {
    /// Copy one base block.
    Copy {
        /// Manifest file index.
        file_index: u32,
        /// Base block index.
        block_index: u32,
        /// Strong BLAKE3-128 checksum the server must verify.
        strong: [u8; 16],
    },
    /// Append `len` literal bytes that follow.
    Literal {
        /// Manifest file index.
        file_index: u32,
        /// Byte count.
        len: u32,
    },
    /// Reuse the base file.
    Unchanged {
        /// Manifest file index.
        file_index: u32,
        /// Whole-file BLAKE3.
        content_hash: [u8; 32],
    },
    /// Finish one file.
    EndFile {
        /// Manifest file index.
        file_index: u32,
    },
    /// Finish the batch.
    EndBatch,
}

impl Instruction {
    /// The opcode.
    pub const fn opcode(&self) -> u8 {
        match self {
            Self::Copy { .. } => 0x01,
            Self::Literal { .. } => 0x02,
            Self::Unchanged { .. } => 0x03,
            Self::EndFile { .. } => 0x04,
            Self::EndBatch => 0x05,
        }
    }

    /// Encoded width of the header; `LITERAL` bytes follow.
    pub const fn header_len(&self) -> usize {
        match self {
            Self::Copy { .. } => 1 + 4 + 4 + 16,
            Self::Literal { .. } => 1 + 4 + 4,
            Self::Unchanged { .. } => 1 + 4 + 32,
            Self::EndFile { .. } => 1 + 4,
            Self::EndBatch => 1,
        }
    }
}

/// Writes an instruction stream.
#[derive(Debug)]
pub struct InstructionWriter<W: Write> {
    inner: W,
    literal_remaining: u32,
    ended: bool,
}

impl<W: Write> InstructionWriter<W> {
    /// Wrap a sink.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            literal_remaining: 0,
            ended: false,
        }
    }

    /// Write one instruction header.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Instruction`] after `END_BATCH`, while a literal is
    /// unfinished, or for an oversized literal; or an I/O error.
    pub fn write(&mut self, instruction: Instruction) -> Result<(), ProtoError> {
        if self.ended {
            return Err(ProtoError::Instruction("instruction after END_BATCH"));
        }
        if self.literal_remaining != 0 {
            return Err(ProtoError::Instruction("literal is not finished"));
        }
        match instruction {
            Instruction::Copy {
                file_index,
                block_index,
                strong,
            } => {
                let mut buf = [0u8; 25];
                buf[0] = 0x01;
                buf[1..5].copy_from_slice(&file_index.to_le_bytes());
                buf[5..9].copy_from_slice(&block_index.to_le_bytes());
                buf[9..].copy_from_slice(&strong);
                self.inner.write_all(&buf)?;
            }
            Instruction::Literal { file_index, len } => {
                if len > MAX_LITERAL {
                    return Err(ProtoError::ValueOutOfRange {
                        tag: super::tag::LITERAL_LEN,
                        value: u64::from(len),
                        max: u64::from(MAX_LITERAL),
                    });
                }
                let mut buf = [0u8; 9];
                buf[0] = 0x02;
                buf[1..5].copy_from_slice(&file_index.to_le_bytes());
                buf[5..9].copy_from_slice(&len.to_le_bytes());
                self.inner.write_all(&buf)?;
                self.literal_remaining = len;
            }
            Instruction::Unchanged {
                file_index,
                content_hash,
            } => {
                let mut buf = [0u8; 37];
                buf[0] = 0x03;
                buf[1..5].copy_from_slice(&file_index.to_le_bytes());
                buf[5..].copy_from_slice(&content_hash);
                self.inner.write_all(&buf)?;
            }
            Instruction::EndFile { file_index } => {
                let mut buf = [0u8; 5];
                buf[0] = 0x04;
                buf[1..5].copy_from_slice(&file_index.to_le_bytes());
                self.inner.write_all(&buf)?;
            }
            Instruction::EndBatch => {
                self.inner.write_all(&[0x05])?;
                self.ended = true;
            }
        }
        Ok(())
    }

    /// Write literal bytes for the open `LITERAL`.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Instruction`] when no literal is open or `bytes` is
    /// longer than the declared length; or an I/O error.
    pub fn write_literal(&mut self, bytes: &[u8]) -> Result<(), ProtoError> {
        if bytes.len() as u64 > u64::from(self.literal_remaining) {
            return Err(ProtoError::Instruction("literal overrun"));
        }
        self.inner.write_all(bytes)?;
        self.literal_remaining -= bytes.len() as u32;
        Ok(())
    }

    /// Write a complete literal in one call.
    ///
    /// # Errors
    ///
    /// Any [`InstructionWriter::write`] or [`InstructionWriter::write_literal`]
    /// error.
    pub fn literal(&mut self, file_index: u32, bytes: &[u8]) -> Result<(), ProtoError> {
        let len = u32::try_from(bytes.len()).map_err(|_| ProtoError::ValueOutOfRange {
            tag: super::tag::LITERAL_LEN,
            value: bytes.len() as u64,
            max: u64::from(MAX_LITERAL),
        })?;
        self.write(Instruction::Literal { file_index, len })?;
        self.write_literal(bytes)
    }

    /// Whether `END_BATCH` was written.
    pub const fn is_ended(&self) -> bool {
        self.ended
    }

    /// Finish the stream and return the sink.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Instruction`] when a literal is unfinished or the batch
    /// was not ended; or an I/O error.
    pub fn finish(mut self) -> Result<W, ProtoError> {
        if self.literal_remaining != 0 {
            return Err(ProtoError::Instruction("unfinished literal"));
        }
        if !self.ended {
            return Err(ProtoError::Instruction("missing END_BATCH"));
        }
        self.inner.flush()?;
        Ok(self.inner)
    }
}

/// Reads an instruction stream.
#[derive(Debug)]
pub struct InstructionReader<R: Read> {
    inner: R,
    literal_remaining: u32,
    ended: bool,
}

impl<R: Read> InstructionReader<R> {
    /// Wrap a source.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            literal_remaining: 0,
            ended: false,
        }
    }

    /// The number of literal bytes still to consume.
    pub const fn literal_remaining(&self) -> u32 {
        self.literal_remaining
    }

    /// Read the next instruction, or `None` after `END_BATCH`.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Instruction`] for an unknown opcode, a truncated header,
    /// an unfinished literal, or bytes after `END_BATCH`.
    pub fn next_instruction(&mut self) -> Result<Option<Instruction>, ProtoError> {
        if self.ended {
            return Ok(None);
        }
        if self.literal_remaining != 0 {
            return Err(ProtoError::Instruction("literal is not finished"));
        }
        let opcode = match read_opcode(&mut self.inner)? {
            Some(opcode) => opcode,
            None => return Err(ProtoError::Instruction("stream ends before END_BATCH")),
        };
        match opcode {
            0x01 => {
                let mut buf = [0u8; 24];
                read_exact(&mut self.inner, &mut buf)?;
                Ok(Some(Instruction::Copy {
                    file_index: read_u32(&buf, 0),
                    block_index: read_u32(&buf, 4),
                    strong: read_16(&buf, 8),
                }))
            }
            0x02 => {
                let mut buf = [0u8; 8];
                read_exact(&mut self.inner, &mut buf)?;
                let file_index = read_u32(&buf, 0);
                let len = read_u32(&buf, 4);
                if len > MAX_LITERAL {
                    return Err(ProtoError::ValueOutOfRange {
                        tag: super::tag::LITERAL_LEN,
                        value: u64::from(len),
                        max: u64::from(MAX_LITERAL),
                    });
                }
                self.literal_remaining = len;
                Ok(Some(Instruction::Literal { file_index, len }))
            }
            0x03 => {
                let mut buf = [0u8; 36];
                read_exact(&mut self.inner, &mut buf)?;
                Ok(Some(Instruction::Unchanged {
                    file_index: read_u32(&buf, 0),
                    content_hash: read_32(&buf, 4),
                }))
            }
            0x04 => {
                let mut buf = [0u8; 4];
                read_exact(&mut self.inner, &mut buf)?;
                Ok(Some(Instruction::EndFile {
                    file_index: u32::from_le_bytes(buf),
                }))
            }
            0x05 => {
                self.ended = true;
                Ok(Some(Instruction::EndBatch))
            }
            other => Err(ProtoError::BadEnum {
                tag: super::tag::INSTRUCTION,
                value: u64::from(other),
            }),
        }
    }

    /// Consume literal bytes. The caller must call this after a
    /// [`Instruction::Literal`] until the declared length is reached.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Instruction`] when no literal is open or `buf` is longer
    /// than the remainder; or an I/O error.
    pub fn read_literal(&mut self, buf: &mut [u8]) -> Result<usize, ProtoError> {
        if buf.is_empty() {
            return Ok(0);
        }
        if buf.len() as u64 > u64::from(self.literal_remaining) {
            return Err(ProtoError::Instruction("literal overrun"));
        }
        let got = self.inner.read(buf)?;
        if got == 0 {
            return Err(ProtoError::Instruction("literal truncated"));
        }
        self.literal_remaining -= got as u32;
        Ok(got)
    }

    /// Read the rest of the open literal into `sink`.
    ///
    /// # Errors
    ///
    /// Any read or write error.
    pub fn copy_literal(&mut self, sink: &mut impl Write) -> Result<u32, ProtoError> {
        let mut copied = 0u32;
        let mut buf = [0u8; 64 * 1024];
        while self.literal_remaining != 0 {
            let want = (self.literal_remaining as usize).min(buf.len());
            let got = self.read_literal(&mut buf[..want])?;
            sink.write_all(&buf[..got])?;
            copied += got as u32;
        }
        Ok(copied)
    }

    /// Whether `END_BATCH` was seen.
    pub const fn is_ended(&self) -> bool {
        self.ended
    }

    /// Finish the stream, rejecting an unfinished literal, a missing
    /// `END_BATCH` or trailing bytes.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Instruction`] or an I/O error.
    pub fn finish(mut self) -> Result<(), ProtoError> {
        if self.literal_remaining != 0 {
            return Err(ProtoError::Instruction("unfinished literal"));
        }
        if !self.ended {
            return Err(ProtoError::Instruction("missing END_BATCH"));
        }
        let mut extra = [0u8; 1];
        match self.inner.read(&mut extra)? {
            0 => Ok(()),
            _ => Err(ProtoError::Instruction("bytes after END_BATCH")),
        }
    }
}

fn read_opcode(reader: &mut impl Read) -> Result<Option<u8>, ProtoError> {
    let mut buf = [0u8; 1];
    match reader.read(&mut buf)? {
        0 => Ok(None),
        _ => Ok(Some(buf[0])),
    }
}

fn read_u32(buf: &[u8], at: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[at..at + 4]);
    u32::from_le_bytes(bytes)
}

fn read_32(buf: &[u8], at: usize) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&buf[at..at + 32]);
    bytes
}

fn read_16(buf: &[u8], at: usize) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&buf[at..at + 16]);
    bytes
}

fn read_exact(reader: &mut impl Read, buf: &mut [u8]) -> Result<(), ProtoError> {
    let mut filled = 0;
    while filled < buf.len() {
        let got = reader.read(&mut buf[filled..])?;
        if got == 0 {
            return Err(ProtoError::Instruction("truncated instruction"));
        }
        filled += got;
    }
    Ok(())
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::io::Cursor;

    fn all_instructions() -> Vec<Instruction> {
        vec![
            Instruction::Copy {
                file_index: 1,
                block_index: 2,
                strong: [0x11; 16],
            },
            Instruction::Literal {
                file_index: 3,
                len: 4,
            },
            Instruction::Unchanged {
                file_index: 5,
                content_hash: [0x22; 32],
            },
            Instruction::EndFile { file_index: 5 },
            Instruction::EndBatch,
        ]
    }

    fn encode_all() -> Vec<u8> {
        let mut writer = InstructionWriter::new(Vec::new());
        for instruction in all_instructions() {
            writer.write(instruction).unwrap();
            if let Instruction::Literal { .. } = instruction {
                writer.write_literal(b"data").unwrap();
            }
        }
        writer.finish().unwrap()
    }

    #[test]
    fn every_instruction_round_trips() {
        let bytes = encode_all();
        let mut reader = InstructionReader::new(Cursor::new(bytes));
        for expected in all_instructions() {
            let got = reader.next_instruction().unwrap().unwrap();
            assert_eq!(got, expected);
            if let Instruction::Literal { len, .. } = got {
                let mut buf = vec![0u8; len as usize];
                assert_eq!(reader.read_literal(&mut buf).unwrap(), len as usize);
                assert_eq!(buf, b"data");
            }
        }
        assert!(reader.next_instruction().unwrap().is_none());
        reader.finish().unwrap();
    }

    #[test]
    fn literal_can_be_streamed_in_pieces() {
        let mut writer = InstructionWriter::new(Vec::new());
        writer
            .write(Instruction::Literal {
                file_index: 0,
                len: 6,
            })
            .unwrap();
        writer.write_literal(b"abc").unwrap();
        writer.write_literal(b"def").unwrap();
        writer.write(Instruction::EndBatch).unwrap();
        let bytes = writer.finish().unwrap();

        let mut reader = InstructionReader::new(Cursor::new(bytes));
        assert!(matches!(
            reader.next_instruction().unwrap(),
            Some(Instruction::Literal { len: 6, .. })
        ));
        let mut sink = Vec::new();
        assert_eq!(reader.copy_literal(&mut sink).unwrap(), 6);
        assert_eq!(sink, b"abcdef");
        assert!(matches!(
            reader.next_instruction().unwrap(),
            Some(Instruction::EndBatch)
        ));
        reader.finish().unwrap();
    }

    #[test]
    fn literal_overrun_and_unfinished_literal_are_rejected() {
        let mut writer = InstructionWriter::new(Vec::new());
        writer
            .write(Instruction::Literal {
                file_index: 0,
                len: 2,
            })
            .unwrap();
        assert!(matches!(
            writer.write_literal(b"abc"),
            Err(ProtoError::Instruction("literal overrun"))
        ));
        assert!(matches!(
            writer.write(Instruction::EndBatch),
            Err(ProtoError::Instruction("literal is not finished"))
        ));
        assert!(matches!(
            writer.finish(),
            Err(ProtoError::Instruction("unfinished literal"))
        ));
    }

    #[test]
    fn missing_end_batch_is_rejected() {
        let mut writer = InstructionWriter::new(Vec::new());
        writer
            .write(Instruction::EndFile { file_index: 0 })
            .unwrap();
        assert!(matches!(
            writer.finish(),
            Err(ProtoError::Instruction("missing END_BATCH"))
        ));
    }

    #[test]
    fn bytes_after_end_batch_are_rejected() {
        let mut bytes = encode_all();
        bytes.push(0x05);
        let mut reader = InstructionReader::new(Cursor::new(bytes));
        while let Some(instruction) = reader.next_instruction().unwrap() {
            if let Instruction::Literal { len, .. } = instruction {
                let mut buf = vec![0u8; len as usize];
                reader.read_literal(&mut buf).unwrap();
            }
        }
        assert!(matches!(
            reader.finish(),
            Err(ProtoError::Instruction("bytes after END_BATCH"))
        ));
    }

    #[test]
    fn truncated_instruction_is_rejected() {
        let bytes = encode_all();
        for cut in 0..bytes.len() {
            let mut reader = InstructionReader::new(Cursor::new(&bytes[..cut]));
            let mut failed = false;
            loop {
                match reader.next_instruction() {
                    Ok(Some(Instruction::Literal { len, .. })) => {
                        let mut buf = vec![0u8; len as usize];
                        if reader.read_literal(&mut buf).is_err() {
                            failed = true;
                            break;
                        }
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }
            if failed {
                continue;
            }
            assert!(reader.finish().is_err(), "prefix of {cut} bytes must fail");
        }
    }

    #[test]
    fn unknown_opcode_and_oversized_literal_are_rejected() {
        let mut reader = InstructionReader::new(Cursor::new(vec![0x77]));
        assert!(matches!(
            reader.next_instruction(),
            Err(ProtoError::BadEnum {
                tag: super::super::tag::INSTRUCTION,
                value: 0x77
            })
        ));

        let mut bytes = vec![0x02];
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(MAX_LITERAL + 1).to_le_bytes());
        let mut reader = InstructionReader::new(Cursor::new(bytes));
        assert!(matches!(
            reader.next_instruction(),
            Err(ProtoError::ValueOutOfRange { .. })
        ));
    }

    #[test]
    fn header_lengths_match_the_encoder() {
        let mut writer = InstructionWriter::new(Vec::new());
        for instruction in [
            Instruction::Copy {
                file_index: 0,
                block_index: 0,
                strong: [0; 16],
            },
            Instruction::Unchanged {
                file_index: 0,
                content_hash: [0; 32],
            },
            Instruction::EndFile { file_index: 0 },
            Instruction::EndBatch,
        ] {
            let before = writer.inner.len();
            writer.write(instruction).unwrap();
            assert_eq!(writer.inner.len() - before, instruction.header_len());
        }
    }
}
