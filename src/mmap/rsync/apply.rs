//! Delta application.
//!
//! Every COPY is checked against the base bytes before it is written:
//! the range must be in bounds, and BLAKE3-128 must match the strong hash in
//! the instruction. A stale signature therefore fails closed instead of
//! copying the wrong bytes.
//!
//! [`apply_exact`] also bounds the output with the manifest size. That bound
//! stops a copy bomb before it can grow memory without limit.

use std::io::Write;

use super::engine::{MAX_APPLY_BYTES, RsyncError};
use super::instruction::Instruction;
use super::strong::strong128;
use super::verify::verify;

/// Output sink for the shared apply loop.
trait Sink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), RsyncError>;
    fn written(&self) -> u64;
}

struct VecSink {
    buffer: Vec<u8>,
}

impl Sink for VecSink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), RsyncError> {
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    fn written(&self) -> u64 {
        self.buffer.len() as u64
    }
}

struct WriteSink<'a, W: Write> {
    out: &'a mut W,
    written: u64,
}

impl<W: Write> Sink for WriteSink<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), RsyncError> {
        self.out.write_all(bytes)?;
        self.written = self.written.saturating_add(bytes.len() as u64);
        Ok(())
    }

    fn written(&self) -> u64 {
        self.written
    }
}

/// Apply a single-file instruction list to `base`.
///
/// The output is capped at [`MAX_APPLY_BYTES`] (4 GiB). Production callers
/// must use [`apply_exact`] with the manifest size, so a copy bomb fails
/// before it can allocate up to the ceiling.
pub fn apply(base: &[u8], instructions: &[Instruction]) -> Result<Vec<u8>, RsyncError> {
    apply_file_core(base, instructions, 0, true, None)
}

/// Apply a single-file instruction list and require `expected` output bytes.
pub fn apply_exact(
    base: &[u8],
    instructions: &[Instruction],
    expected: u64,
) -> Result<Vec<u8>, RsyncError> {
    apply_file_core(base, instructions, 0, true, Some(expected))
}

/// Apply the instructions of one file inside a multi-file stream.
pub fn apply_file(
    base: &[u8],
    instructions: &[Instruction],
    file: u32,
) -> Result<Vec<u8>, RsyncError> {
    apply_file_core(base, instructions, file, false, None)
}

/// Apply one file and require `expected` output bytes.
pub fn apply_file_exact(
    base: &[u8],
    instructions: &[Instruction],
    file: u32,
    expected: u64,
) -> Result<Vec<u8>, RsyncError> {
    apply_file_core(base, instructions, file, false, Some(expected))
}

/// Apply a single-file instruction list into a writer.
pub fn apply_to<W: Write>(
    base: &[u8],
    instructions: &[Instruction],
    expected: Option<u64>,
    out: &mut W,
) -> Result<u64, RsyncError> {
    apply_file_to(base, instructions, 0, true, expected, out)
}

/// Apply one file's instructions into a writer.
pub fn apply_file_to<W: Write>(
    base: &[u8],
    instructions: &[Instruction],
    file: u32,
    strict: bool,
    expected: Option<u64>,
    out: &mut W,
) -> Result<u64, RsyncError> {
    let mut sink = WriteSink { out, written: 0 };
    apply_core(base, instructions, file, strict, expected, &mut sink)
}

fn apply_file_core(
    base: &[u8],
    instructions: &[Instruction],
    file: u32,
    strict: bool,
    expected: Option<u64>,
) -> Result<Vec<u8>, RsyncError> {
    let mut sink = VecSink { buffer: Vec::new() };
    apply_core(base, instructions, file, strict, expected, &mut sink)?;
    Ok(sink.buffer)
}

fn apply_core<S: Sink>(
    base: &[u8],
    instructions: &[Instruction],
    target: u32,
    strict: bool,
    expected: Option<u64>,
    sink: &mut S,
) -> Result<u64, RsyncError> {
    let limit = expected.unwrap_or(MAX_APPLY_BYTES);
    let mut ended_file = false;
    let mut ended_batch = false;
    for instruction in instructions {
        if ended_batch {
            return Err(RsyncError::BadInstruction("instruction after END_BATCH"));
        }
        if matches!(instruction, Instruction::EndBatch) {
            ended_batch = true;
            continue;
        }
        let file = instruction
            .file()
            .ok_or(RsyncError::BadInstruction("missing file index"))?;
        if file != target {
            if strict {
                return Err(RsyncError::BadInstruction(
                    "file index does not match the target",
                ));
            }
            continue;
        }
        if ended_file {
            return Err(RsyncError::BadInstruction("instruction after END_FILE"));
        }
        match instruction {
            Instruction::Literal { bytes, .. } => {
                write_checked(sink, bytes, limit)?;
            }
            Instruction::Copy {
                block,
                offset,
                len,
                strong,
                ..
            } => {
                if *len == 0 {
                    return Err(RsyncError::BadInstruction("zero-length copy"));
                }
                let end =
                    offset
                        .checked_add(u64::from(*len))
                        .ok_or(RsyncError::CopyOutOfBounds {
                            offset: *offset,
                            len: *len,
                            base_len: base.len() as u64,
                        })?;
                if end > base.len() as u64 {
                    return Err(RsyncError::CopyOutOfBounds {
                        offset: *offset,
                        len: *len,
                        base_len: base.len() as u64,
                    });
                }
                let start = *offset as usize;
                let end = end as usize;
                let range = &base[start..end];
                if strong128(range) != *strong {
                    return Err(RsyncError::StrongMismatch { block: *block });
                }
                write_checked(sink, range, limit)?;
            }
            Instruction::Unchanged { content_hash, .. } => {
                if !verify(base, base.len() as u64, content_hash) {
                    return Err(RsyncError::HashMismatch);
                }
                write_checked(sink, base, limit)?;
            }
            Instruction::EndFile { .. } => {
                ended_file = true;
            }
            Instruction::EndBatch => {}
        }
    }
    if !ended_batch {
        return Err(RsyncError::BadInstruction("missing END_BATCH"));
    }
    if !ended_file {
        return Err(RsyncError::BadInstruction("missing END_FILE"));
    }
    let written = sink.written();
    if let Some(expected) = expected {
        if written != expected {
            return Err(RsyncError::LengthMismatch {
                expected,
                actual: written,
            });
        }
    }
    Ok(written)
}

fn write_checked<S: Sink>(sink: &mut S, bytes: &[u8], limit: u64) -> Result<(), RsyncError> {
    let next = sink
        .written()
        .checked_add(bytes.len() as u64)
        .ok_or(RsyncError::OutputTooLarge { max: limit })?;
    if next > limit {
        return Err(RsyncError::OutputTooLarge { max: limit });
    }
    sink.write(bytes)
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::mmap::rsync::delta::delta;
    use crate::mmap::rsync::signature::sign;
    use crate::mmap::rsync::strong::{file_hash, strong128};
    use std::io::Cursor;

    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.push(state as u8);
        }
        out
    }

    fn roundtrip(basis: &[u8], new: &[u8], block_size: u32) -> Vec<Instruction> {
        let signature = sign(Cursor::new(basis), block_size).unwrap();
        let instructions = delta(new, &signature).unwrap();
        assert_eq!(apply(basis, &instructions).unwrap(), new);
        instructions
    }

    #[test]
    fn u_rsync_apply_roundtrip() {
        let basis = noise(100_000, 0x41);
        let mut new = basis.clone();
        new[10_000..10_100].fill(0x99);
        let instructions = roundtrip(&basis, &new, 2048);
        assert_eq!(
            apply_exact(&basis, &instructions, new.len() as u64).unwrap(),
            new
        );
    }

    #[test]
    fn u_rsync_apply_empty_file() {
        let signature = sign(Cursor::new(Vec::<u8>::new()), 1024).unwrap();
        let instructions = delta(&[], &signature).unwrap();
        assert_eq!(
            apply_exact(&[], &instructions, 0).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn u_rsync_apply_exact_rejects_wrong_length() {
        let basis = noise(4096, 0x42);
        let signature = sign(Cursor::new(&basis), 1024).unwrap();
        let instructions = delta(&basis, &signature).unwrap();
        assert!(matches!(
            apply_exact(&basis, &instructions, 8192),
            Err(RsyncError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn u_rsync_apply_rejects_out_of_bounds() {
        let base = vec![7u8; 1024];
        let instructions = vec![
            Instruction::Copy {
                file: 0,
                block: 0,
                offset: 1000,
                len: 100,
                strong: strong128(&base[1000..1024]),
            },
            Instruction::EndFile { file: 0 },
            Instruction::EndBatch,
        ];
        assert!(matches!(
            apply(&base, &instructions),
            Err(RsyncError::CopyOutOfBounds { .. })
        ));

        let instructions = vec![
            Instruction::Copy {
                file: 0,
                block: 0,
                offset: u64::MAX,
                len: 2,
                strong: [0u8; 16],
            },
            Instruction::EndFile { file: 0 },
            Instruction::EndBatch,
        ];
        assert!(matches!(
            apply(&base, &instructions),
            Err(RsyncError::CopyOutOfBounds { .. })
        ));
    }

    #[test]
    fn u_rsync_apply_rejects_copy_bomb() {
        let base = vec![7u8; 4096];
        let strong = strong128(&base);
        let mut instructions = Vec::new();
        for _ in 0..64 {
            instructions.push(Instruction::Copy {
                file: 0,
                block: 0,
                offset: 0,
                len: 4096,
                strong,
            });
        }
        instructions.push(Instruction::EndFile { file: 0 });
        instructions.push(Instruction::EndBatch);
        assert!(matches!(
            apply_exact(&base, &instructions, 4096),
            Err(RsyncError::OutputTooLarge { .. })
        ));
    }

    #[test]
    fn u_rsync_apply_rejects_strong_mismatch() {
        let base = noise(4096, 0x43);
        let instructions = vec![
            Instruction::Copy {
                file: 0,
                block: 0,
                offset: 0,
                len: 1024,
                strong: [0u8; 16],
            },
            Instruction::EndFile { file: 0 },
            Instruction::EndBatch,
        ];
        assert!(matches!(
            apply(&base, &instructions),
            Err(RsyncError::StrongMismatch { .. })
        ));
    }

    #[test]
    fn u_rsync_apply_unchanged_hash_check() {
        let base = noise(4096, 0x44);
        let good = vec![
            Instruction::Unchanged {
                file: 0,
                content_hash: file_hash(&base),
            },
            Instruction::EndFile { file: 0 },
            Instruction::EndBatch,
        ];
        assert_eq!(apply(&base, &good).unwrap(), base);

        let bad = vec![
            Instruction::Unchanged {
                file: 0,
                content_hash: [0u8; 32],
            },
            Instruction::EndFile { file: 0 },
            Instruction::EndBatch,
        ];
        assert!(matches!(apply(&base, &bad), Err(RsyncError::HashMismatch)));
    }

    #[test]
    fn u_rsync_apply_rejects_missing_end_and_trailing() {
        let base = noise(1024, 0x45);
        let missing = vec![Instruction::EndFile { file: 0 }];
        assert!(matches!(
            apply(&base, &missing),
            Err(RsyncError::BadInstruction(_))
        ));

        let trailing = vec![
            Instruction::EndFile { file: 0 },
            Instruction::EndBatch,
            Instruction::Literal {
                file: 0,
                bytes: vec![1],
            },
        ];
        assert!(matches!(
            apply(&base, &trailing),
            Err(RsyncError::BadInstruction(_))
        ));
    }

    #[test]
    fn u_rsync_apply_rejects_foreign_file_index() {
        let base = noise(1024, 0x46);
        let instructions = vec![
            Instruction::Literal {
                file: 1,
                bytes: vec![1],
            },
            Instruction::EndFile { file: 1 },
            Instruction::EndBatch,
        ];
        assert!(matches!(
            apply(&base, &instructions),
            Err(RsyncError::BadInstruction(_))
        ));
        assert_eq!(apply_file(&base, &instructions, 1).unwrap(), vec![1u8]);
    }

    #[test]
    fn u_rsync_apply_to_streams() {
        let base = noise(100_000, 0x47);
        let mut new = base.clone();
        new[50_000..50_010].fill(0x11);
        let signature = sign(Cursor::new(&base), 2048).unwrap();
        let instructions = delta(&new, &signature).unwrap();

        let mut out = Vec::new();
        let written = apply_to(&base, &instructions, Some(new.len() as u64), &mut out).unwrap();
        assert_eq!(written, new.len() as u64);
        assert_eq!(out, new);
    }
}
