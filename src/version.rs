//! Version layers: software, protocol, frame, WCP, rsync backend, signature.
//!
//! Each layer evolves independently (46 §6.1). Build-time values are
//! injected by `build.rs` when present; the skeleton falls back to
//! `unknown` so a source checkout without git metadata still builds.

/// Cargo package version.
pub const SOFTWARE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// HELLO/WELCOME `major.minor`.
pub const PROTOCOL_VERSION: &str = "1.0";

/// Frame header `ver` byte.
pub const FRAME_VERSION: u8 = 1;

/// `F_WCP_VER` field.
pub const WCP_VERSION: u8 = 1;

/// The only rsync backend.
pub const RSYNC_BACKEND: &str = "oxide";

/// Client-to-client signature algorithm.
pub const SIG_ALG: &str = "ed25519";

/// Git commit injected by `build.rs`; `unknown` without metadata.
pub fn git_sha() -> &'static str {
    option_env!("SYNCMOUNT_GIT_SHA").unwrap_or("unknown")
}

/// Build target triple injected by `build.rs`; host arch otherwise.
pub fn build_target() -> &'static str {
    option_env!("SYNCMOUNT_BUILD_TARGET").unwrap_or(std::env::consts::ARCH)
}

/// Build profile injected by `build.rs`; `unknown` without metadata.
pub fn build_profile() -> &'static str {
    option_env!("SYNCMOUNT_BUILD_PROFILE").unwrap_or("unknown")
}

/// One-line version string printed by `--version`.
pub fn long_version() -> String {
    format!(
        "{SOFTWARE_VERSION} (git {}, {}, {}, proto {PROTOCOL_VERSION}, frame {FRAME_VERSION}, wcp {WCP_VERSION}, rsync {RSYNC_BACKEND}, sig {SIG_ALG})",
        git_sha(),
        build_target(),
        build_profile(),
    )
}
