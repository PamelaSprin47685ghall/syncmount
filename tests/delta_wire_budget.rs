//! Wire-size budget for the rsync delta engine.
//!
//! The base is a deterministic 8 MiB buffer signed at
//! `block_size_for(BASE_BYTES)` (4096 bytes, so 2048 blocks):
//!
//! * identical: every data record is COPY; wire is at most 1% of the base.
//! * 1% changed in one contiguous region: wire is at most 5% of the base.
//! * unrelated content: wire is at most 115% of the base, because the literal
//!   path adds only a 9-byte record header per 64 KiB chunk.
//!
//! Wire bytes are the 8-byte stream header plus `Instruction::encoded_len`
//! for every record. The engine always ends a delta with END_FILE and
//! END_BATCH, so both records are counted. The test prints the observed
//! percentage of every case.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use syncmount::mmap::rsync::{
    INSTRUCTION_HEADER_BYTES, Instruction, Signature, apply_exact, block_size_for, decode_from,
    delta_to, file_hash, sign, verify,
};

/// Base size. 8 MiB keeps every percentage meaningful while a debug run of the
/// unrelated case still scans only one buffer.
const BASE_BYTES: usize = 8 * 1024 * 1024;

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

struct Budget {
    wire_bytes: usize,
    literal_bytes: u64,
    copied_bytes: u64,
    instructions: Vec<Instruction>,
}

fn payload_bytes(instructions: &[Instruction]) -> (u64, u64) {
    let mut literal = 0u64;
    let mut copied = 0u64;
    for instruction in instructions {
        match instruction {
            Instruction::Literal { bytes, .. } => literal += bytes.len() as u64,
            Instruction::Copy { len, .. } => copied += u64::from(*len),
            _ => {}
        }
    }
    (literal, copied)
}

/// Stream one delta, decode it, and cross-check the byte counters.
fn measure(new: &[u8], signature: &Signature) -> Budget {
    let mut stream = Vec::new();
    let stats = delta_to(new, signature, &mut stream).unwrap();
    let instructions = decode_from(stream.as_slice()).unwrap();
    let encoded: usize = instructions.iter().map(Instruction::encoded_len).sum();
    let wire_bytes = INSTRUCTION_HEADER_BYTES + encoded;
    assert_eq!(wire_bytes, stream.len());
    assert_eq!(stats.local_bytes, new.len() as u64);
    assert_eq!(stats.literal_bytes + stats.copied_bytes, new.len() as u64);
    let (literal_bytes, copied_bytes) = payload_bytes(&instructions);
    assert_eq!(literal_bytes, stats.literal_bytes);
    assert_eq!(copied_bytes, stats.copied_bytes);
    Budget {
        wire_bytes,
        literal_bytes,
        copied_bytes,
        instructions,
    }
}

fn percent(wire_bytes: usize) -> f64 {
    wire_bytes as f64 * 100.0 / BASE_BYTES as f64
}

fn check_applied(base: &[u8], new: &[u8], instructions: &[Instruction]) {
    let patched = apply_exact(base, instructions, new.len() as u64).unwrap();
    assert_eq!(&patched, new);
    assert!(verify(new, new.len() as u64, &file_hash(new)));
}

fn report(label: &str, budget: &Budget) {
    println!(
        "{label}: wire={} B ({:.3}% of base), copy={} B, literal={} B, records={}",
        budget.wire_bytes,
        percent(budget.wire_bytes),
        budget.copied_bytes,
        budget.literal_bytes,
        budget.instructions.len()
    );
}

#[test]
fn delta_stays_within_the_wire_budget() {
    let base = noise(BASE_BYTES, 0x9001);
    let block_size = block_size_for(BASE_BYTES as u64);
    assert_eq!(block_size, 4096);
    let signature = sign(Cursor::new(&base), block_size).unwrap();
    assert_eq!(signature.len(), BASE_BYTES / block_size as usize);

    let identical = measure(&base, &signature);
    report("identical", &identical);
    assert_eq!(identical.literal_bytes, 0);
    assert_eq!(identical.copied_bytes, BASE_BYTES as u64);
    assert!(
        !identical
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Instruction::Literal { .. }))
    );
    let copies = identical
        .instructions
        .iter()
        .filter(|instruction| matches!(instruction, Instruction::Copy { .. }))
        .count();
    assert_eq!(copies, signature.len());
    assert!(
        identical
            .instructions
            .contains(&Instruction::EndFile { file: 0 })
    );
    assert_eq!(identical.instructions.last(), Some(&Instruction::EndBatch));
    assert!(
        percent(identical.wire_bytes) <= 1.0,
        "identical wire={} B",
        identical.wire_bytes
    );
    check_applied(&base, &base, &identical.instructions);

    let changed_len = BASE_BYTES / 100;
    let changed_start = 2_000_000;
    let mut one_percent = base.clone();
    one_percent[changed_start..changed_start + changed_len].fill(0xee);
    let one_percent_budget = measure(&one_percent, &signature);
    report("one-percent-changed", &one_percent_budget);
    assert!(one_percent_budget.literal_bytes >= changed_len as u64);
    assert!(one_percent_budget.copied_bytes > 0);
    assert!(
        percent(one_percent_budget.wire_bytes) <= 5.0,
        "one-percent wire={} B",
        one_percent_budget.wire_bytes
    );
    check_applied(&base, &one_percent, &one_percent_budget.instructions);

    let unrelated = noise(BASE_BYTES, 0x9002);
    let unrelated_budget = measure(&unrelated, &signature);
    report("unrelated", &unrelated_budget);
    assert_eq!(unrelated_budget.copied_bytes, 0);
    assert_eq!(unrelated_budget.literal_bytes, unrelated.len() as u64);
    assert!(
        percent(unrelated_budget.wire_bytes) <= 115.0,
        "unrelated wire={} B",
        unrelated_budget.wire_bytes
    );
    check_applied(&base, &unrelated, &unrelated_budget.instructions);
}
