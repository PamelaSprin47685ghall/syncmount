//! Rolling delta search.
//!
//! The scanner keeps one `block_size` window. It tests the window weak
//! checksum against a sorted index, confirms a hit with BLAKE3-128, and then
//! emits COPY. A miss rolls one byte into the literal buffer. The reader path
//! keeps at most one window plus 64 KiB of lookahead.

use std::io::{self, Read, Write};

use super::engine::{LITERAL_CHUNK_BYTES, RsyncError, SegmentPolicy};
use super::instruction::{self, Instruction};
use super::signature::{BlockSignature, Signature};
use super::strong::{StrongHash, strong128};
use super::weak::WeakState;

/// Bytes read ahead by the streaming scanner.
const LOOKAHEAD_BYTES: usize = 64 * 1024;

/// Counters for one delta pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeltaStats {
    /// Local bytes consumed.
    pub local_bytes: u64,
    /// Bytes emitted as LITERAL.
    pub literal_bytes: u64,
    /// Bytes emitted as COPY.
    pub copied_bytes: u64,
    /// Number of LITERAL and COPY records.
    pub instructions: u64,
}

/// Weak-checksum index over one signature.
struct SignatureIndex<'a> {
    entries: Vec<(u32, u32)>,
    s1_bits: Box<[u64; 1024]>,
    blocks: &'a [BlockSignature],
    block_size: u32,
}

impl<'a> SignatureIndex<'a> {
    fn new(signature: &'a Signature) -> Self {
        let blocks = signature.blocks();
        let mut entries = Vec::with_capacity(blocks.len());
        let mut s1_bits = Box::new([0u64; 1024]);
        for (index, block) in blocks.iter().enumerate() {
            let weak = block.weak();
            entries.push((weak, index as u32));
            let s1 = (weak & 0xffff) as usize;
            s1_bits[s1 / 64] |= 1u64 << (s1 % 64);
        }
        entries.sort_unstable_by_key(|(weak, _)| *weak);
        Self {
            entries,
            s1_bits,
            blocks,
            block_size: signature.block_size(),
        }
    }

    fn find(&self, window: &[u8], weak: u32) -> Option<(u32, &'a BlockSignature)> {
        let s1 = (weak & 0xffff) as usize;
        if self.s1_bits[s1 / 64] & (1u64 << (s1 % 64)) == 0 {
            return None;
        }
        let start = self
            .entries
            .partition_point(|(entry_weak, _)| *entry_weak < weak);
        let mut strong: Option<StrongHash> = None;
        for &(entry_weak, index) in &self.entries[start..] {
            if entry_weak != weak {
                break;
            }
            let block = &self.blocks[index as usize];
            if block.len() as usize != window.len() {
                continue;
            }
            let strong = strong.get_or_insert_with(|| strong128(window));
            if *block.strong() == *strong {
                return Some((index, block));
            }
        }
        None
    }
}

trait Scanner {
    fn window(&self) -> &[u8];
    fn weak(&self) -> u32;
    fn can_roll(&mut self) -> Result<bool, RsyncError>;
    fn roll(&mut self) -> u8;
    fn consume_window(&mut self) -> Result<bool, RsyncError>;
    fn take_window(&mut self) -> Vec<u8>;
}

struct SliceScanner<'a> {
    data: &'a [u8],
    pos: usize,
    len: usize,
    block_size: usize,
    weak: WeakState,
}

impl<'a> SliceScanner<'a> {
    fn new(data: &'a [u8], block_size: usize) -> Self {
        let len = data.len().min(block_size);
        let weak = WeakState::new(&data[..len]);
        Self {
            data,
            pos: 0,
            len,
            block_size,
            weak,
        }
    }
}

impl Scanner for SliceScanner<'_> {
    fn window(&self) -> &[u8] {
        &self.data[self.pos..self.pos + self.len]
    }

    fn weak(&self) -> u32 {
        self.weak.weak()
    }

    fn can_roll(&mut self) -> Result<bool, RsyncError> {
        Ok(self.pos + self.len < self.data.len())
    }

    fn roll(&mut self) -> u8 {
        let out = self.data[self.pos];
        let incoming = self.data[self.pos + self.len];
        self.weak.rotate(out, incoming);
        self.pos += 1;
        out
    }

    fn consume_window(&mut self) -> Result<bool, RsyncError> {
        self.pos += self.len;
        self.len = (self.data.len() - self.pos).min(self.block_size);
        if self.len == 0 {
            return Ok(false);
        }
        self.weak = WeakState::new(&self.data[self.pos..self.pos + self.len]);
        Ok(true)
    }

    fn take_window(&mut self) -> Vec<u8> {
        let out = self.data[self.pos..self.pos + self.len].to_vec();
        self.pos += self.len;
        self.len = 0;
        out
    }
}

struct ReaderScanner<R: Read> {
    reader: R,
    buf: Vec<u8>,
    scratch: Vec<u8>,
    start: usize,
    len: usize,
    block_size: usize,
    eof: bool,
    weak: WeakState,
}

impl<R: Read> ReaderScanner<R> {
    fn new(reader: R, block_size: usize) -> Result<Self, RsyncError> {
        let mut scanner = Self {
            reader,
            buf: Vec::with_capacity(block_size + 2 * LOOKAHEAD_BYTES),
            scratch: vec![0u8; LOOKAHEAD_BYTES],
            start: 0,
            len: 0,
            block_size,
            eof: false,
            weak: WeakState::default(),
        };
        scanner.fill(block_size + LOOKAHEAD_BYTES)?;
        scanner.len = scanner.available().min(block_size);
        if scanner.len < block_size {
            scanner.eof = true;
        }
        if scanner.len > 0 {
            scanner.weak = WeakState::new(scanner.window());
        }
        Ok(scanner)
    }

    fn available(&self) -> usize {
        self.buf.len() - self.start
    }

    fn compact(&mut self) {
        if self.start == 0 {
            return;
        }
        let remaining = self.buf.len() - self.start;
        self.buf.copy_within(self.start.., 0);
        self.buf.truncate(remaining);
        self.start = 0;
    }

    fn fill(&mut self, want: usize) -> Result<(), RsyncError> {
        while self.available() < want && !self.eof {
            if self.buf.capacity() - self.buf.len() < LOOKAHEAD_BYTES {
                self.compact();
                self.buf.reserve(LOOKAHEAD_BYTES);
            }
            match self.reader.read(&mut self.scratch) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(read) => self.buf.extend_from_slice(&self.scratch[..read]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(RsyncError::Io(error)),
            }
        }
        Ok(())
    }
}

impl<R: Read> Scanner for ReaderScanner<R> {
    fn window(&self) -> &[u8] {
        &self.buf[self.start..self.start + self.len]
    }

    fn weak(&self) -> u32 {
        self.weak.weak()
    }

    fn can_roll(&mut self) -> Result<bool, RsyncError> {
        if self.start + self.len < self.buf.len() {
            return Ok(true);
        }
        if self.eof {
            return Ok(false);
        }
        self.fill(self.block_size + LOOKAHEAD_BYTES)?;
        Ok(self.start + self.len < self.buf.len())
    }

    fn roll(&mut self) -> u8 {
        let out = self.buf[self.start];
        let incoming = self.buf[self.start + self.len];
        self.weak.rotate(out, incoming);
        self.start += 1;
        out
    }

    fn consume_window(&mut self) -> Result<bool, RsyncError> {
        self.start += self.len;
        self.len = 0;
        self.fill(self.block_size + LOOKAHEAD_BYTES)?;
        self.len = self.available().min(self.block_size);
        if self.len == 0 {
            return Ok(false);
        }
        self.weak = WeakState::new(self.window());
        Ok(true)
    }

    fn take_window(&mut self) -> Vec<u8> {
        let out = self.buf[self.start..self.start + self.len].to_vec();
        self.start += self.len;
        self.len = 0;
        out
    }
}

trait Emitter {
    fn literal(&mut self, file: u32, bytes: &[u8]) -> Result<(), RsyncError>;
    fn copy(
        &mut self,
        file: u32,
        block: u32,
        offset: u64,
        entry: &BlockSignature,
    ) -> Result<(), RsyncError>;
    fn end_file(&mut self, file: u32) -> Result<(), RsyncError>;
    fn end_batch(&mut self) -> Result<(), RsyncError>;
}

#[derive(Debug, Default)]
struct VecEmitter {
    instructions: Vec<Instruction>,
}

impl VecEmitter {
    fn into_inner(self) -> Vec<Instruction> {
        self.instructions
    }
}

impl Emitter for VecEmitter {
    fn literal(&mut self, file: u32, bytes: &[u8]) -> Result<(), RsyncError> {
        self.instructions.push(Instruction::Literal {
            file,
            bytes: bytes.to_vec(),
        });
        Ok(())
    }

    fn copy(
        &mut self,
        file: u32,
        block: u32,
        offset: u64,
        entry: &BlockSignature,
    ) -> Result<(), RsyncError> {
        self.instructions.push(Instruction::Copy {
            file,
            block,
            offset,
            len: entry.len(),
            strong: *entry.strong(),
        });
        Ok(())
    }

    fn end_file(&mut self, file: u32) -> Result<(), RsyncError> {
        self.instructions.push(Instruction::EndFile { file });
        Ok(())
    }

    fn end_batch(&mut self) -> Result<(), RsyncError> {
        self.instructions.push(Instruction::EndBatch);
        Ok(())
    }
}

struct WriteEmitter<'a, W: Write> {
    out: &'a mut W,
}

impl<'a, W: Write> WriteEmitter<'a, W> {
    fn new(out: &'a mut W) -> Result<Self, RsyncError> {
        instruction::write_header(out)?;
        Ok(Self { out })
    }
}

impl<W: Write> Emitter for WriteEmitter<'_, W> {
    fn literal(&mut self, file: u32, bytes: &[u8]) -> Result<(), RsyncError> {
        instruction::write_literal(self.out, file, bytes)
    }

    fn copy(
        &mut self,
        file: u32,
        block: u32,
        offset: u64,
        entry: &BlockSignature,
    ) -> Result<(), RsyncError> {
        instruction::write_copy(self.out, file, block, offset, entry.len(), entry.strong())
    }

    fn end_file(&mut self, file: u32) -> Result<(), RsyncError> {
        instruction::write_end_file(self.out, file)
    }

    fn end_batch(&mut self) -> Result<(), RsyncError> {
        instruction::write_end_batch(self.out)
    }
}

fn diff<S: Scanner, E: Emitter>(
    scanner: &mut S,
    index: &SignatureIndex<'_>,
    emitter: &mut E,
) -> Result<DeltaStats, RsyncError> {
    let mut literal = Vec::with_capacity(LITERAL_CHUNK_BYTES);
    let mut stats = DeltaStats::default();
    loop {
        if scanner.window().is_empty() {
            break;
        }
        let weak = scanner.weak();
        let matched = index.find(scanner.window(), weak);
        if let Some((block_index, entry)) = matched {
            flush_literal(&mut literal, emitter, &mut stats)?;
            let offset = u64::from(block_index) * u64::from(index.block_size);
            emitter.copy(0, block_index, offset, entry)?;
            stats.copied_bytes = stats.copied_bytes.saturating_add(u64::from(entry.len()));
            stats.instructions += 1;
            if !scanner.consume_window()? {
                break;
            }
            continue;
        }
        if scanner.can_roll()? {
            let out = scanner.roll();
            literal.push(out);
            if literal.len() == LITERAL_CHUNK_BYTES {
                flush_literal(&mut literal, emitter, &mut stats)?;
            }
            continue;
        }
        // The rolled-out bytes come before the final window. Flush them
        // first, or the output would rotate.
        flush_literal(&mut literal, emitter, &mut stats)?;
        let tail = scanner.take_window();
        for chunk in tail.chunks(LITERAL_CHUNK_BYTES) {
            emitter.literal(0, chunk)?;
            stats.literal_bytes += chunk.len() as u64;
            stats.instructions += 1;
        }
        break;
    }
    flush_literal(&mut literal, emitter, &mut stats)?;
    emitter.end_file(0)?;
    emitter.end_batch()?;
    stats.local_bytes = stats.literal_bytes + stats.copied_bytes;
    Ok(stats)
}

fn flush_literal<E: Emitter>(
    literal: &mut Vec<u8>,
    emitter: &mut E,
    stats: &mut DeltaStats,
) -> Result<(), RsyncError> {
    if literal.is_empty() {
        return Ok(());
    }
    emitter.literal(0, literal)?;
    stats.literal_bytes += literal.len() as u64;
    stats.instructions += 1;
    literal.clear();
    Ok(())
}

/// Compute the delta between `local` and a base signature.
///
/// This path holds the local segment in memory. Use [`delta_to`] for a
/// stream. A delta is computed for one segment; callers must not pass a whole
/// 4 GiB file unless they accept the instruction-vector cost.
pub fn delta(local: &[u8], signature: &Signature) -> Result<Vec<Instruction>, RsyncError> {
    signature.validate()?;
    let index = SignatureIndex::new(signature);
    let mut scanner = SliceScanner::new(local, signature.block_size() as usize);
    let mut emitter = VecEmitter::default();
    diff(&mut scanner, &index, &mut emitter)?;
    Ok(emitter.into_inner())
}

/// Stream a delta instruction stream into `out`.
///
/// The scanner keeps one window plus 64 KiB of lookahead. A failed call may
/// leave a partial stream in `out`; the caller must discard it.
pub fn delta_to<R: Read, W: Write>(
    local: R,
    signature: &Signature,
    out: &mut W,
) -> Result<DeltaStats, RsyncError> {
    signature.validate()?;
    let index = SignatureIndex::new(signature);
    let mut scanner = ReaderScanner::new(local, signature.block_size() as usize)?;
    let mut emitter = WriteEmitter::new(out)?;
    diff(&mut scanner, &index, &mut emitter)
}

/// Delta one segment and bind the signature to `policy`.
pub fn delta_with_policy(
    local: &[u8],
    signature: &Signature,
    policy: &SegmentPolicy,
) -> Result<Vec<Instruction>, RsyncError> {
    policy.validate()?;
    signature.check_policy(policy)?;
    if local.len() as u64 > policy.segment_bytes as u64 {
        return Err(RsyncError::SegmentTooLarge {
            len: local.len() as u64,
            max: policy.segment_bytes as u64,
        });
    }
    let instructions = delta(local, signature)?;
    let encoded: usize = instructions.iter().map(Instruction::encoded_len).sum();
    if encoded > policy.max_delta_bytes() {
        return Err(RsyncError::DeltaTooLarge {
            len: encoded,
            max: policy.max_delta_bytes(),
        });
    }
    Ok(instructions)
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::mmap::rsync::apply::apply;
    use crate::mmap::rsync::instruction::{decode_from, encode_to};
    use crate::mmap::rsync::signature::sign;
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

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut out, "{byte:02x}").unwrap();
        }
        out
    }

    fn roundtrip(basis: &[u8], new: &[u8], block_size: u32) -> (Vec<u8>, Vec<Instruction>) {
        let signature = sign(Cursor::new(basis), block_size).unwrap();
        let instructions = delta(new, &signature).unwrap();
        let patched = apply(basis, &instructions).unwrap();
        (patched, instructions)
    }

    fn literal_bytes(instructions: &[Instruction]) -> u64 {
        instructions
            .iter()
            .map(|instruction| match instruction {
                Instruction::Literal { bytes, .. } => bytes.len() as u64,
                _ => 0,
            })
            .sum()
    }

    fn copied_bytes(instructions: &[Instruction]) -> u64 {
        instructions
            .iter()
            .map(|instruction| match instruction {
                Instruction::Copy { len, .. } => u64::from(*len),
                _ => 0,
            })
            .sum()
    }

    #[test]
    fn u_rsync_delta_golden_vector() {
        let basis: Vec<u8> = (0..4096).map(|index| (index % 251) as u8).collect();
        let mut new = basis.clone();
        new.push(0xaa);
        let signature = sign(Cursor::new(&basis), 1024).unwrap();
        let instructions = delta(&new, &signature).unwrap();
        let mut encoded = Vec::new();
        encode_to(&instructions, &mut encoded).unwrap();

        assert_eq!(
            hex(&signature.to_bytes()),
            "534d523101000010000004000000000000001000000000042ad0eafa0000040042214739f095a406f3fc83deb889744a9ec0ec8a00000400f82d9b29da6db93924de1475c47b8e14f1f0ee1a00000400cfec53ee42495dae4e7aafadff886b6e2460efaa00000400566bb36275e407a4ecf33673098627fa"
        );
        assert_eq!(
            hex(&encoded),
            "534d44310100000002000000000000000000000000000000000000040042214739f095a406f3fc83deb889744a020000000000000001000000000000040000000400f82d9b29da6db93924de1475c47b8e14020000000000000002000000000000080000000400cfec53ee42495dae4e7aafadff886b6e0200000000000000030000000000000c0000000400566bb36275e407a4ecf33673098627fa010000000000000001aa040000000005"
        );
        assert_eq!(apply(&basis, &instructions).unwrap(), new);
    }

    #[test]
    fn u_rsync_delta_roundtrip_sizes() {
        let sizes = [0usize, 1, 1023, 1024, 1025, 4096, 65_536, 100_000];
        for (seed, size) in sizes.iter().enumerate() {
            let basis = noise(*size, 0x100 + seed as u64);
            let mut new = basis.clone();
            if !new.is_empty() {
                let middle = new.len() / 2;
                new[middle] ^= 0x5a;
            }
            let block_size = crate::mmap::rsync::engine::block_size_for(*size as u64);
            let (patched, instructions) = roundtrip(&basis, &new, block_size);
            assert_eq!(patched, new, "size={size}");
            assert_eq!(
                literal_bytes(&instructions) + copied_bytes(&instructions),
                new.len() as u64,
                "size={size}"
            );
        }
    }

    #[test]
    fn u_rsync_delta_empty_file() {
        let signature = sign(Cursor::new(Vec::<u8>::new()), 1024).unwrap();
        let instructions = delta(&[], &signature).unwrap();
        assert_eq!(
            instructions,
            vec![Instruction::EndFile { file: 0 }, Instruction::EndBatch]
        );
        assert_eq!(apply(&[], &instructions).unwrap(), Vec::<u8>::new());

        let new = noise(4096, 0x22);
        let instructions = delta(&new, &signature).unwrap();
        assert_eq!(apply(&[], &instructions).unwrap(), new);
    }

    #[test]
    fn u_rsync_delta_one_byte_insert_at_head() {
        let basis = noise(1024 * 1024, 0x33);
        let mut new = Vec::with_capacity(basis.len() + 1);
        new.push(0xab);
        new.extend_from_slice(&basis);
        let (patched, instructions) = roundtrip(&basis, &new, 2048);
        assert_eq!(patched, new);
        assert!(literal_bytes(&instructions) <= 4096);
        assert!(copied_bytes(&instructions) >= basis.len() as u64 - 4096);
        let encoded: usize = instructions.iter().map(Instruction::encoded_len).sum();
        assert!(encoded < new.len() / 10, "encoded={encoded}");
    }

    #[test]
    fn u_rsync_delta_one_byte_delete_at_head() {
        let basis = noise(1024 * 1024, 0x34);
        let new = basis[1..].to_vec();
        let (patched, instructions) = roundtrip(&basis, &new, 2048);
        assert_eq!(patched, new);
        assert!(literal_bytes(&instructions) <= 4096);
        assert!(copied_bytes(&instructions) >= new.len() as u64 - 4096);
        let encoded: usize = instructions.iter().map(Instruction::encoded_len).sum();
        assert!(encoded < new.len() / 10, "encoded={encoded}");
    }

    #[test]
    fn u_rsync_delta_tail_is_short() {
        let basis = noise(10_000, 0x35);
        let (patched, instructions) = roundtrip(&basis, &basis, 1024);
        assert_eq!(patched, basis);
        assert_eq!(literal_bytes(&instructions), 0);
        assert_eq!(copied_bytes(&instructions), basis.len() as u64);
        assert!(
            instructions
                .iter()
                .any(|instruction| matches!(instruction, Instruction::Copy { len: 784, .. }))
        );
    }

    #[test]
    fn u_rsync_delta_weak_collision_needs_strong() {
        let mut left = vec![0u8; 64 * 1024];
        let mut right = vec![0u8; 64 * 1024];
        left[0] = 0x00;
        left[512] = 0x80;
        right[0] = 0x80;
        right[512] = 0x00;
        let left_weak = WeakState::new(&left).weak();
        let right_weak = WeakState::new(&right).weak();
        assert_eq!(left_weak, right_weak);
        assert_ne!(strong128(&left), strong128(&right));

        let signature = sign(Cursor::new(&left), 64 * 1024).unwrap();
        let instructions = delta(&right, &signature).unwrap();
        assert!(
            !instructions
                .iter()
                .any(|instruction| matches!(instruction, Instruction::Copy { .. }))
        );
        assert_eq!(apply(&left, &instructions).unwrap(), right);
    }

    #[test]
    fn u_rsync_delta_weak_collision_tries_every_candidate() {
        let mut left = vec![0u8; 64 * 1024];
        let mut right = vec![0u8; 64 * 1024];
        left[0] = 0x00;
        left[512] = 0x80;
        right[0] = 0x80;
        right[512] = 0x00;
        assert_eq!(WeakState::new(&left).weak(), WeakState::new(&right).weak());

        let mut basis = left.clone();
        basis.extend_from_slice(&right);
        let signature = sign(Cursor::new(&basis), 64 * 1024).unwrap();
        assert_eq!(signature.len(), 2);
        let instructions = delta(&right, &signature).unwrap();
        assert!(instructions.iter().any(|instruction| matches!(
            instruction,
            Instruction::Copy {
                block: 1,
                len: 65536,
                ..
            }
        )));
        assert_eq!(apply(&basis, &instructions).unwrap(), right);
    }

    #[test]
    fn u_rsync_delta_repeated_blocks() {
        let basis = vec![0u8; 1024 * 1024];
        let mut new = basis.clone();
        new[500_000] = 1;
        let (patched, instructions) = roundtrip(&basis, &new, 4096);
        assert_eq!(patched, new);
        assert!(literal_bytes(&instructions) <= 4096);
        assert!(copied_bytes(&instructions) >= 1024 * 1024 - 4096);
    }

    #[test]
    fn u_rsync_delta_stale_signature_is_rejected_by_apply() {
        let basis = noise(16 * 1024, 0x36);
        let mut new = basis.clone();
        new[100] ^= 0x5a;
        let signature = sign(Cursor::new(&basis), 1024).unwrap();
        let instructions = delta(&new, &signature).unwrap();

        let mut changed_base = basis.clone();
        changed_base[2048] ^= 0xff;
        assert!(matches!(
            apply(&changed_base, &instructions),
            Err(RsyncError::StrongMismatch { .. })
        ));
    }

    #[test]
    fn u_rsync_delta_byte_budget() {
        let basis = noise(4 * 1024 * 1024, 0x37);
        let signature = sign(Cursor::new(&basis), 2048).unwrap();

        let unchanged = delta(&basis, &signature).unwrap();
        assert_eq!(literal_bytes(&unchanged), 0);
        assert_eq!(copied_bytes(&unchanged), basis.len() as u64);
        assert_eq!(
            unchanged
                .iter()
                .map(Instruction::encoded_len)
                .sum::<usize>(),
            2048 * 37 + 5 + 1
        );

        let mut one_percent = basis.clone();
        let changed = 40 * 1024;
        one_percent[1_000_000..1_000_000 + changed].fill(0xee);
        let one_percent_delta = delta(&one_percent, &signature).unwrap();
        let encoded: usize = one_percent_delta.iter().map(Instruction::encoded_len).sum();
        assert!(
            encoded <= changed + 128 * 1024,
            "encoded={encoded} changed={changed}"
        );
        assert_eq!(apply(&basis, &one_percent_delta).unwrap(), one_percent);

        let different = noise(4 * 1024 * 1024, 0x38);
        let different_delta = delta(&different, &signature).unwrap();
        let encoded: usize = different_delta.iter().map(Instruction::encoded_len).sum();
        assert!(encoded <= different.len() + 256 * 1024, "encoded={encoded}");
        assert!(literal_bytes(&different_delta) >= different.len() as u64);
        assert_eq!(apply(&basis, &different_delta).unwrap(), different);
    }

    #[test]
    fn u_rsync_delta_stream_matches_vec() {
        let basis = noise(200_000, 0x39);
        let mut new = basis.clone();
        new[50_000..50_100].fill(0x77);
        new.splice(120_000..120_000, [1u8, 2, 3, 4]);
        let signature = sign(Cursor::new(&basis), 2048).unwrap();
        let expected = delta(&new, &signature).unwrap();

        let mut streamed = Vec::new();
        let stats = delta_to(Cursor::new(&new), &signature, &mut streamed).unwrap();
        let decoded = decode_from(Cursor::new(&streamed)).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(stats.local_bytes, new.len() as u64);
        assert_eq!(stats.literal_bytes + stats.copied_bytes, new.len() as u64);
    }

    #[test]
    fn u_rsync_delta_to_reads_in_bounded_chunks() {
        struct BoundedReader {
            remaining: usize,
            max_request: usize,
        }
        impl Read for BoundedReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                assert!(buffer.len() <= LOOKAHEAD_BYTES, "request={}", buffer.len());
                self.max_request = self.max_request.max(buffer.len());
                let take = buffer.len().min(self.remaining).min(1024);
                for (index, byte) in buffer[..take].iter_mut().enumerate() {
                    *byte = ((self.remaining + index) % 251) as u8;
                }
                self.remaining -= take;
                Ok(take)
            }
        }

        let reader = BoundedReader {
            remaining: 256 * 1024,
            max_request: 0,
        };
        let signature = sign(Cursor::new(vec![0u8; 1024]), 1024).unwrap();
        let mut out = Vec::new();
        let stats = delta_to(reader, &signature, &mut out).unwrap();
        assert_eq!(stats.local_bytes, 256 * 1024);
        assert!(out.len() >= 256 * 1024);
    }

    #[test]
    fn u_rsync_delta_with_policy_rejects_mismatch() {
        let basis = noise(4096, 0x3a);
        let new = basis.clone();
        let signature = sign(Cursor::new(&basis), 1024).unwrap();
        let policy = SegmentPolicy {
            block_size: 1024,
            ..SegmentPolicy::DEFAULT
        };
        assert!(delta_with_policy(&new, &signature, &policy).is_ok());

        let wrong = SegmentPolicy {
            block_size: 2048,
            ..SegmentPolicy::DEFAULT
        };
        assert!(matches!(
            delta_with_policy(&new, &signature, &wrong),
            Err(RsyncError::BlockSizeMismatch { .. })
        ));

        let small = SegmentPolicy {
            segment_bytes: 2048,
            chunk_bytes: 1024,
            block_size: 1024,
            ..SegmentPolicy::DEFAULT
        };
        assert!(matches!(
            delta_with_policy(&new, &signature, &small),
            Err(RsyncError::SegmentTooLarge { .. })
        ));
    }
}
