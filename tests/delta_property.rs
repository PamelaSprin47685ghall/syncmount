//! Randomized property checks for the rsync delta engine.
//!
//! Two properties run 64 cases each:
//!
//! 1. A random basis of at most 64 KiB, changed by one random edit (replace a
//!    range, insert, delete, append, truncate or reverse), always reconstructs
//!    exactly.
//! 2. A random basis and a random target of at most 32 KiB reconstruct exactly
//!    even when they share no blocks.
//!
//! The basis is signed with `block_size_for(basis.len())`, the same rule the
//! engine uses for a whole file.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use proptest::prelude::*;
use syncmount::mmap::rsync::{apply_exact, block_size_for, delta, file_hash, sign, verify};

/// Apply one random edit. Every index is reduced modulo the valid range, so a
/// generated value can never slice out of bounds.
fn mutate(old: &[u8], kind: u8, a: usize, b: usize, payload: &[u8]) -> Vec<u8> {
    match kind % 6 {
        0 => {
            let start = a % (old.len() + 1);
            let len = b % (old.len() - start + 1);
            let mut new = Vec::with_capacity(old.len() - len + payload.len());
            new.extend_from_slice(&old[..start]);
            new.extend_from_slice(payload);
            new.extend_from_slice(&old[start + len..]);
            new
        }
        1 => {
            let at = a % (old.len() + 1);
            let mut new = Vec::with_capacity(old.len() + payload.len());
            new.extend_from_slice(&old[..at]);
            new.extend_from_slice(payload);
            new.extend_from_slice(&old[at..]);
            new
        }
        2 => {
            let start = a % (old.len() + 1);
            let len = b % (old.len() - start + 1);
            let mut new = Vec::with_capacity(old.len() - len);
            new.extend_from_slice(&old[..start]);
            new.extend_from_slice(&old[start + len..]);
            new
        }
        3 => {
            let mut new = old.to_vec();
            new.extend_from_slice(payload);
            new
        }
        4 => {
            let keep = a % (old.len() + 1);
            old[..keep].to_vec()
        }
        _ => {
            let mut new = old.to_vec();
            let start = a % (new.len() + 1);
            let end = start + b % (new.len() - start + 1);
            new[start..end].reverse();
            new
        }
    }
}

fn check_roundtrip(old: &[u8], new: &[u8]) -> Result<(), TestCaseError> {
    let block_size = block_size_for(old.len() as u64);
    let signature = sign(Cursor::new(old), block_size).unwrap();
    let instructions = delta(new, &signature).unwrap();
    let patched = apply_exact(old, &instructions, new.len() as u64).unwrap();
    prop_assert_eq!(patched.as_slice(), new);
    prop_assert!(verify(new, new.len() as u64, &file_hash(new)));
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn mutated_basis_reconstructs(
        old in prop::collection::vec(any::<u8>(), 0..=65_536usize),
        kind in 0u8..6,
        a in any::<usize>(),
        b in any::<usize>(),
        payload in prop::collection::vec(any::<u8>(), 0..=2_048usize),
    ) {
        let new = mutate(&old, kind, a, b, &payload);
        check_roundtrip(&old, &new)?;
    }

    #[test]
    fn unrelated_data_reconstructs(
        old in prop::collection::vec(any::<u8>(), 0..=32_768usize),
        new in prop::collection::vec(any::<u8>(), 0..=32_768usize),
    ) {
        check_roundtrip(&old, &new)?;
    }
}
