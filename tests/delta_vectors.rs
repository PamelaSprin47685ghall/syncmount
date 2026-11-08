//! Fixed-vector checks for the rsync delta engine.
//!
//! Each file length gets one signature at `block_size_for(len)` and five
//! deterministic edits: replace the middle block, insert one byte at the head,
//! delete one byte at the head, append a tail, and truncate. Every edit must
//! reconstruct with `apply_exact` and hash to the expected BLAKE3-256.
//!
//! The same test also pins the block shape at the empty, one-block and
//! block-boundary lengths, and builds one multi-file instruction stream with a
//! single END_BATCH.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use syncmount::mmap::rsync::{
    FilePlan, FilePlanKind, Instruction, SIGNATURE_ENTRY_BYTES, SIGNATURE_HEADER_BYTES,
    apply_exact, apply_file_exact, block_count_for, block_size_for, decode_from, delta, encode_to,
    file_hash, sign, verify,
};

/// Deterministic xorshift noise.
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

/// Flip every byte of the middle signature block. An empty basis has no block
/// to replace, so it becomes fresh content and exercises the literal path.
fn replace_middle_block(old: &[u8], block_size: u32) -> Vec<u8> {
    if old.is_empty() {
        return vec![0x7e; 300];
    }
    let block = block_size as usize;
    let start = (old.len() / 2 / block) * block;
    let end = (start + block).min(old.len());
    let mut new = old.to_vec();
    for byte in &mut new[start..end] {
        *byte ^= 0xff;
    }
    new
}

fn insert_at_head(old: &[u8], _block_size: u32) -> Vec<u8> {
    let mut new = Vec::with_capacity(old.len() + 1);
    new.push(0xab);
    new.extend_from_slice(old);
    new
}

fn delete_at_head(old: &[u8], _block_size: u32) -> Vec<u8> {
    if old.is_empty() {
        Vec::new()
    } else {
        old[1..].to_vec()
    }
}

fn append_tail(old: &[u8], _block_size: u32) -> Vec<u8> {
    let mut new = old.to_vec();
    new.extend_from_slice(b"appended-tail-17b");
    new
}

fn truncate_to_three_quarters(old: &[u8], _block_size: u32) -> Vec<u8> {
    let keep = old.len() * 3 / 4;
    old[..keep].to_vec()
}

fn retag_file(instructions: &[Instruction], file: u32) -> Vec<Instruction> {
    let mut out = Vec::with_capacity(instructions.len());
    for instruction in instructions {
        match instruction {
            Instruction::Literal { bytes, .. } => out.push(Instruction::Literal {
                file,
                bytes: bytes.clone(),
            }),
            Instruction::Copy {
                block,
                offset,
                len,
                strong,
                ..
            } => out.push(Instruction::Copy {
                file,
                block: *block,
                offset: *offset,
                len: *len,
                strong: *strong,
            }),
            Instruction::Unchanged { content_hash, .. } => out.push(Instruction::Unchanged {
                file,
                content_hash: *content_hash,
            }),
            Instruction::EndFile { .. } => out.push(Instruction::EndFile { file }),
            Instruction::EndBatch => {}
        }
    }
    out
}

#[test]
fn delta_roundtrips_across_sizes_and_mutations() {
    type Mutation = fn(&[u8], u32) -> Vec<u8>;
    let sizes = [
        0usize,
        1,
        1023,
        1024,
        65_535,
        65_536,
        65_537,
        1024 * 1024 + 17,
    ];
    let mutations: [(&str, Mutation); 5] = [
        ("replace-middle-block", replace_middle_block),
        ("insert-head", insert_at_head),
        ("delete-head", delete_at_head),
        ("append-tail", append_tail),
        ("truncate", truncate_to_three_quarters),
    ];

    for (seed, len) in sizes.iter().enumerate() {
        let old = noise(*len, 0x500 + seed as u64);
        let block_size = block_size_for(*len as u64);
        let plan = FilePlan::for_len(*len as u64);
        assert_eq!(plan.kind, FilePlanKind::Delta, "len={len}");
        assert_eq!(plan.block_size, block_size, "len={len}");
        assert_eq!(
            plan.block_count,
            block_count_for(*len as u64, block_size),
            "len={len}"
        );
        assert!(!plan.is_full(), "len={len}");

        let signature = sign(Cursor::new(&old), block_size).unwrap();
        assert_eq!(signature.basis_len(), *len as u64);
        assert_eq!(signature.len() as u64, plan.block_count);

        for (name, mutate) in mutations {
            let new = mutate(&old, block_size);
            let instructions = delta(&new, &signature).unwrap();
            let patched = apply_exact(&old, &instructions, new.len() as u64)
                .unwrap_or_else(|error| panic!("len={len} mutation={name}: {error}"));
            assert_eq!(patched, new, "len={len} mutation={name}");
            assert!(
                verify(&new, new.len() as u64, &file_hash(&new)),
                "len={len} mutation={name}"
            );
        }
    }
}

#[test]
fn empty_one_block_and_boundary_shapes() {
    let cases = [
        (0usize, 1024u32, 0u64, 0u32),
        (1, 1024, 1, 1),
        (1023, 1024, 1, 1023),
        (1024, 1024, 1, 1024),
        (65_535, 1024, 64, 1023),
        (65_536, 1024, 64, 1024),
        (65_537, 1024, 65, 1),
        (1024 * 1024 + 17, 2048, 513, 17),
    ];

    for (seed, (len, block_size, blocks, last_len)) in cases.into_iter().enumerate() {
        assert_eq!(block_size_for(len as u64), block_size, "len={len}");
        assert_eq!(block_count_for(len as u64, block_size), blocks, "len={len}");

        let data = noise(len, 0x600 + seed as u64);
        let signature = sign(Cursor::new(&data), block_size).unwrap();
        assert_eq!(signature.basis_len(), len as u64);
        assert_eq!(signature.block_size(), block_size);
        assert_eq!(signature.len() as u64, blocks);
        assert_eq!(
            signature.encoded_len(),
            SIGNATURE_HEADER_BYTES + blocks as usize * SIGNATURE_ENTRY_BYTES
        );

        if blocks == 0 {
            assert!(signature.is_empty());
            assert!(signature.block(0).is_none());
        } else {
            let last = signature.block(blocks as u32 - 1).unwrap();
            assert_eq!(last.len(), last_len, "len={len}");
            assert_eq!(
                last.len() as usize,
                data.len() - (blocks as usize - 1) * block_size as usize,
                "len={len}"
            );
        }
    }
}

#[test]
fn empty_basis_emits_only_literals() {
    let signature = sign(Cursor::new(Vec::<u8>::new()), block_size_for(0)).unwrap();
    let instructions = delta(&[], &signature).unwrap();
    assert_eq!(
        instructions,
        vec![Instruction::EndFile { file: 0 }, Instruction::EndBatch]
    );
    assert_eq!(
        apply_exact(&[], &instructions, 0).unwrap(),
        Vec::<u8>::new()
    );

    let new = noise(100_000, 0x701);
    let instructions = delta(&new, &signature).unwrap();
    assert!(
        !instructions
            .iter()
            .any(|instruction| matches!(instruction, Instruction::Copy { .. }))
    );
    let literals: Vec<&Instruction> = instructions
        .iter()
        .filter(|instruction| matches!(instruction, Instruction::Literal { .. }))
        .collect();
    // Rolls stop one full block before the end; that final window becomes its
    // own literal record after the residual rolled bytes.
    let block_size = signature.block_size() as usize;
    let expected_literals = (new.len() - block_size).div_ceil(64 * 1024) + 1;
    assert_eq!(literals.len(), expected_literals);
    let mut literal_total = 0usize;
    for instruction in literals {
        if let Instruction::Literal { bytes, .. } = instruction {
            assert!(!bytes.is_empty());
            assert!(bytes.len() <= 64 * 1024);
            literal_total += bytes.len();
        }
    }
    assert_eq!(literal_total, new.len());
    let patched = apply_exact(&[], &instructions, new.len() as u64).unwrap();
    assert_eq!(patched, new);
    assert!(verify(&new, new.len() as u64, &file_hash(&new)));
}

#[test]
fn multi_file_stream_roundtrips() {
    let files: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (Vec::new(), Vec::new()),
        {
            let base = noise(3000, 0x801);
            let mut new = base.clone();
            new[1000..1200].fill(0x42);
            new.extend_from_slice(b"tail");
            (base, new)
        },
        {
            let base = noise(70_000, 0x802);
            let mut new = Vec::with_capacity(base.len() + 1);
            new.push(0xcd);
            new.extend_from_slice(&base);
            (base, new)
        },
    ];

    let mut stream = Vec::new();
    for (file, (base, new)) in files.iter().enumerate() {
        let block_size = block_size_for(base.len() as u64);
        let signature = sign(Cursor::new(base), block_size).unwrap();
        let instructions = delta(new, &signature).unwrap();
        assert!(matches!(
            instructions.get(instructions.len() - 2),
            Some(Instruction::EndFile { file: 0 })
        ));
        assert_eq!(instructions.last(), Some(&Instruction::EndBatch));
        stream.extend(retag_file(&instructions, file as u32));
    }
    stream.push(Instruction::EndBatch);

    let mut bytes = Vec::new();
    encode_to(&stream, &mut bytes).unwrap();
    let decoded = decode_from(Cursor::new(&bytes)).unwrap();
    assert_eq!(decoded, stream);

    for (file, (base, new)) in files.iter().enumerate() {
        let patched = apply_file_exact(base, &decoded, file as u32, new.len() as u64)
            .unwrap_or_else(|error| panic!("file={file}: {error}"));
        assert_eq!(&patched, new, "file={file}");
        assert!(
            verify(new, new.len() as u64, &file_hash(new)),
            "file={file}"
        );
    }
}
