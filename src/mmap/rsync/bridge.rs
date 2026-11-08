//! Blocking-pool bridge for the rsync engine.
//!
//! The engine is CPU-bound. The bridge moves owned buffers into
//! `tokio::task::spawn_blocking` and returns owned results. No borrow or
//! stream crosses the thread boundary, and signing does not consume the basis
//! that a later apply may need.

use std::sync::Arc;

use super::apply::apply;
use super::delta::{delta, delta_with_policy};
use super::engine::{RsyncError, SegmentPolicy};
use super::instruction::Instruction;
use super::signature::{Signature, sign, sign_segment};

/// Cheap-to-clone handle that runs engine calls on the blocking pool.
#[derive(Clone, Copy, Debug, Default)]
pub struct EngineBridge;

impl EngineBridge {
    /// Build a bridge. It holds no state.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Sign a basis buffer.
    pub async fn sign(&self, basis: Arc<[u8]>, block_size: u32) -> Result<Signature, RsyncError> {
        tokio::task::spawn_blocking(move || sign(&basis[..], block_size)).await?
    }

    /// Sign one segment under `policy`.
    pub async fn sign_segment(
        &self,
        basis: Arc<[u8]>,
        policy: SegmentPolicy,
    ) -> Result<Signature, RsyncError> {
        tokio::task::spawn_blocking(move || sign_segment(&basis[..], &policy)).await?
    }

    /// Compute a delta from a signature and the new bytes.
    pub async fn delta(
        &self,
        signature: Signature,
        new: Arc<[u8]>,
    ) -> Result<Vec<Instruction>, RsyncError> {
        tokio::task::spawn_blocking(move || delta(&new, &signature)).await?
    }

    /// Compute a delta bound to `policy`.
    pub async fn delta_with_policy(
        &self,
        signature: Signature,
        new: Arc<[u8]>,
        policy: SegmentPolicy,
    ) -> Result<Vec<Instruction>, RsyncError> {
        tokio::task::spawn_blocking(move || delta_with_policy(&new, &signature, &policy)).await?
    }

    /// Apply an instruction list to the basis.
    pub async fn apply(
        &self,
        basis: Arc<[u8]>,
        instructions: Vec<Instruction>,
    ) -> Result<Vec<u8>, RsyncError> {
        tokio::task::spawn_blocking(move || apply(&basis, &instructions)).await?
    }
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

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

    #[tokio::test]
    async fn u_rsync_bridge_roundtrip() {
        let basis = noise(100_000, 0x51);
        let mut new = basis.clone();
        new[50_000..50_010].fill(0x11);

        let bridge = EngineBridge::new();
        let basis_arc: Arc<[u8]> = Arc::from(basis.clone());
        let signature = bridge.sign(Arc::clone(&basis_arc), 2048).await.unwrap();
        let instructions = bridge
            .delta(signature, Arc::from(new.clone()))
            .await
            .unwrap();
        let patched = bridge.apply(basis_arc, instructions).await.unwrap();
        assert_eq!(patched, new);
    }

    #[tokio::test]
    async fn u_rsync_bridge_sign_segment() {
        let basis: Arc<[u8]> = Arc::from(noise(8192, 0x52));
        let policy = SegmentPolicy {
            block_size: 1024,
            ..SegmentPolicy::DEFAULT
        };
        let signature = EngineBridge::new()
            .sign_segment(basis, policy)
            .await
            .unwrap();
        assert_eq!(signature.block_size(), 1024);
        assert_eq!(signature.len(), 8);
    }
}
