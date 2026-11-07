//! syncmount — end-to-end encrypted, eventually consistent FUSE filesystem.
//!
//! Module tree and dependency direction are fixed by the build skeleton
//! (`docs/build.md`, W1). Leaves are `protocol` and `transport`; `client`
//! never depends on `fuse`; `server` never depends on `store` or `client`.
//!
//! This crate is a skeleton: every module is declared so that owners can
//! land implementations without touching this file.

#![forbid(unsafe_code)]

pub mod cli;
pub mod client;
pub mod crypto;
pub mod logging;
pub mod protocol;
pub mod server;
pub mod state;
pub mod store;
pub mod transport;
pub mod version;

#[cfg(feature = "fuse")]
pub mod fuse;

pub use cli::run;

// Frame widths are a wire-format contract (48; build skeleton §9.6). If an
// owner changes the layout, this crate stops compiling instead of shipping a
// silently incompatible header.
const _: () = {
    assert!(protocol::frame::HEADER_LEN == 21);
    assert!(protocol::frame::ROUTE_PREFIX_LEN == 25);
    assert!(protocol::frame::CTRL_PREFIX_LEN == 18);
};
