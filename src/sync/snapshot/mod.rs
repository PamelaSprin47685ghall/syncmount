//! Snapshot capture, generation, publication and installation.
//!
//! Owner: W14 (E7). See 43 §2.
//!
//! # Division of labour
//!
//! | step | type | what it owns |
//! |---|---|---|
//! | capture | [`capture`] | `O(1)` image handle at one `covered_seq` |
//! | generate | [`generator::Generator`] | serialize → parts → seal → index → reference |
//! | install | [`install::Installer`] | pull → verify → digest → install |
//! | drive | `sync::SyncEngine` | phase transitions and notices |
//!
//! There is no `SnapshotService` object on purpose: generation and
//! installation never share mutable state, and the actor already sequences
//! them. A wrapper would only forward calls.
//!
//! # The grant is not stored here
//!
//! `SNAPSHOT_OFFER`/`SNAPSHOT_GRANT` choose a generator on the server
//! (43 §2.3). A client's only local rule is
//! [`generator::Generator::should_offer`], which says when an offer is due; the
//! grant itself arrives as a control message and is the caller's to honour or
//! drop.
//!
//! The file is `generator.rs`, not `gen.rs` as 43 writes it: `gen` is a
//! reserved keyword in edition 2024, so the module cannot carry that name.
//!
//! # Retention
//!
//! A client keeps the last [`crate::sync::config::SNAPSHOT_KEEP`] covered
//! sequences. Eviction is safe because every snapshot chunk is
//! content-addressed and can be regenerated from any member's plaintext; the
//! chunk cache's LRU is the only reclaimer (43 §5.6).

pub mod capture;
pub mod format;
pub mod generator;
pub mod install;

pub use capture::{Captured, capture_at, capture_current};
pub use format::{DataPartHeader, INDEX_FIXED_LEN, SnapshotIndex};
pub use generator::{Bundle, Generator};
pub use install::{Installed, Installer, Pulled};
