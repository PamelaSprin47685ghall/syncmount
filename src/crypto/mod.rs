//! Secrets that are not part of the wire format: master password input and
//! Argon2id stretching.
//!
//! Dependency direction: this module may use `protocol::{crypto, frame,
//! version}` for shared identifiers, but `protocol` never uses `crypto`.
//! Both the client and the server derive the PSK here; the server needs it to
//! decrypt `ORDERED` frames for validation and persistence.
//!
//! * [`secret`] resolves the master password and runs Argon2id.

pub mod secret;

pub use secret::{MasterKey, SecretError};
