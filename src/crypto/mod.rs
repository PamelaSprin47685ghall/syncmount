//! Secrets and identity that are not part of the wire format: master password
//! input, JOIN_PROOF, Ed25519 key persistence.
//!
//! Dependency direction: this module may use `protocol::{crypto, frame,
//! version}` for shared identifiers and the key ring, but `protocol` never
//! uses `crypto`. The server has no `crypto` dependency: it never sees a
//! password, a seed, or a plaintext proof.
//!
//! * [`secret`] resolves the master password and runs Argon2id.
//! * [`proof`] seals and opens JOIN_PROOF, binding `sign_pub`.
//! * [`sign`] persists and uses the per-client Ed25519 key.

pub mod proof;
pub mod secret;
pub mod sign;

pub use proof::{Proof, ProofError};
pub use secret::{MasterKey, SecretError};
pub use sign::{
    SignError, SigningKey, client_id_for, keyentry_input, keyproof_input, skid_for, verify_strict,
};
