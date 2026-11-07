//! Blocking-pool bridge for [`DeltaEngine`].
//!
//! `librsync_oxide` is CPU-bound and works on whole in-memory slices. The
//! bridge moves one owned segment into `tokio::task::spawn_blocking` and
//! returns an owned result; no stream or borrow crosses the thread boundary.
//! That keeps the async actor free of rsync CPU time and bounds each worker to
//! three segments (basis + new + delta).

use std::sync::Arc;

use super::engine::{DeltaEngine, DeltaError};

/// Cheap-to-clone handle that runs engine calls on the blocking pool.
#[derive(Clone, Debug)]
pub struct EngineBridge {
    engine: Arc<dyn DeltaEngine>,
}

impl EngineBridge {
    /// Wrap an engine implementation.
    #[must_use]
    pub fn new<E>(engine: E) -> Self
    where
        E: DeltaEngine + 'static,
    {
        Self {
            engine: Arc::new(engine),
        }
    }

    /// Wrap an already-shared engine.
    #[must_use]
    pub fn from_arc(engine: Arc<dyn DeltaEngine>) -> Self {
        Self { engine }
    }

    /// The wrapped engine, for direct synchronous calls in tests.
    #[must_use]
    pub fn engine(&self) -> &dyn DeltaEngine {
        self.engine.as_ref()
    }

    /// Run [`DeltaEngine::signature`] off the async worker.
    pub async fn signature(&self, basis: Vec<u8>) -> Result<Vec<u8>, DeltaError> {
        let engine = Arc::clone(&self.engine);
        tokio::task::spawn_blocking(move || engine.signature(&basis)).await?
    }

    /// Run [`DeltaEngine::delta`] off the async worker.
    pub async fn delta(&self, signature: Vec<u8>, new: Vec<u8>) -> Result<Vec<u8>, DeltaError> {
        let engine = Arc::clone(&self.engine);
        tokio::task::spawn_blocking(move || engine.delta(&signature, &new)).await?
    }

    /// Run [`DeltaEngine::patch`] off the async worker.
    pub async fn patch(&self, basis: Vec<u8>, delta: Vec<u8>) -> Result<Vec<u8>, DeltaError> {
        let engine = Arc::clone(&self.engine);
        tokio::task::spawn_blocking(move || engine.patch(&basis, &delta)).await?
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::sync::rsync::OxideEngine;

    /// 51:P1-3 — a full segment round-trip crosses the blocking boundary
    /// without sharing a buffer.
    #[tokio::test]
    async fn u_rsync_bridge_roundtrip() {
        let basis: Vec<u8> = (0..100_000u32)
            .map(|index| (index.wrapping_mul(31) ^ (index >> 8)) as u8)
            .collect();
        let mut new = basis.clone();
        new[50_000..50_010].copy_from_slice(b"0123456789");

        let bridge = EngineBridge::new(OxideEngine::default());
        let signature = bridge.signature(basis.clone()).await.unwrap();
        let delta = bridge.delta(signature, new.clone()).await.unwrap();
        let patched = bridge.patch(basis, delta).await.unwrap();
        assert_eq!(patched, new);
    }

    /// 51:P1-3 — an already-shared engine can be bridged without cloning it.
    #[tokio::test]
    async fn u_rsync_bridge_from_arc() {
        let engine: Arc<dyn DeltaEngine> = Arc::new(OxideEngine::default());
        let bridge = EngineBridge::from_arc(Arc::clone(&engine));
        let signature = bridge.signature(Vec::new()).await.unwrap();
        assert_eq!(signature.len(), 12);
        assert_eq!(bridge.engine().signature(&[]).unwrap(), signature);
    }
}
