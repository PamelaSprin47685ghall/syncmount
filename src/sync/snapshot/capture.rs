//! Capture a state image at one sequence number.
//!
//! Owner: W14 (E7). See 43 §2.1.
//!
//! Capture must be `O(1)`: the replay state is copy-on-write, so the provider
//! hands out an immutable root and keeps applying ops on a new one. The
//! generator then serializes in its own thread without pausing apply.
//!
//! # The one invariant capture enforces
//!
//! `covered_seq` and the image are the same fact (C-28). A provider whose
//! applied sequence moved between the decision to capture and the capture
//! itself would otherwise produce a container whose name lies about its
//! content. [`capture_at`] refuses that instead of writing a snapshot nobody
//! can trust.

use std::sync::Arc;

use crate::protocol::frame::Seq;
use crate::sync::{StateImage, StateProvider, SyncError};

/// A captured image and the sequence it covers.
#[derive(Clone, Debug)]
pub struct Captured {
    /// Immutable state root.
    pub image: Arc<dyn StateImage>,
    /// Sequence the image covers; always `image.covered_seq()`.
    pub covered_seq: Seq,
}

/// Capture at `covered_seq`.
///
/// # Errors
///
/// [`SyncError::CoveredSeqMismatch`] when the provider's applied sequence or
/// the captured image disagrees with `covered_seq`.
pub fn capture_at(state: &dyn StateProvider, covered_seq: Seq) -> Result<Captured, SyncError> {
    let image = state.capture();
    let image_seq = image.covered_seq();
    if image_seq != covered_seq {
        return Err(SyncError::CoveredSeqMismatch {
            expected: covered_seq,
            found: image_seq,
        });
    }
    let applied = state.applied_seq();
    if applied != covered_seq {
        return Err(SyncError::CoveredSeqMismatch {
            expected: covered_seq,
            found: applied,
        });
    }
    Ok(Captured { image, covered_seq })
}

/// Capture at the provider's current applied sequence.
///
/// # Errors
///
/// Same as [`capture_at`]; in practice only a provider that moved between the
/// two reads can fail here, which is exactly the race worth reporting.
pub fn capture_current(state: &dyn StateProvider) -> Result<Captured, SyncError> {
    capture_at(state, state.applied_seq())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::sync::test_support::{FakeState, make_image};

    /// C-28: capture refuses an image that does not cover the named sequence.
    #[test]
    fn u_capture_rejects_wrong_sequence() {
        let state = FakeState::new(4096, make_image(4096, &[("a", 1)], 64));
        assert_eq!(
            capture_at(state.as_ref(), Seq(8192)).unwrap_err(),
            SyncError::CoveredSeqMismatch {
                expected: Seq(8192),
                found: Seq(4096),
            }
        );
        let captured = capture_at(state.as_ref(), Seq(4096)).unwrap();
        assert_eq!(captured.covered_seq, Seq(4096));
        assert_eq!(captured.image.covered_seq(), Seq(4096));
        assert_eq!(captured.image.encode().len(), 64);
    }

    /// The current capture uses `applied_seq` and never guesses.
    #[test]
    fn u_capture_current_uses_applied() {
        let state = FakeState::new(7, make_image(7, &[], 0));
        assert_eq!(capture_current(state.as_ref()).unwrap().covered_seq, Seq(7));
    }
}
