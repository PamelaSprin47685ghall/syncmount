//! Version and capability negotiation.
//!
//! Four version layers are independent (44 §6): frame format, protocol
//! major/minor, WCP field version and capability bits. Only the frame format
//! and protocol/caps layers live here; WCP field parsing belongs to the
//! message layer and merely reuses [`WcpVer`].

use std::fmt;

/// Frame-format version byte at header offset 1.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrameVer(u8);

impl FrameVer {
    /// Version 1, the only version this crate writes.
    pub const V1: Self = Self(1);
    /// The version written by every encoder.
    pub const CURRENT: Self = Self::V1;

    /// Raw byte.
    pub const fn get(self) -> u8 {
        self.0
    }

    /// Whether a raw byte names a version this crate can decode.
    pub const fn is_supported_raw(raw: u8) -> bool {
        raw == Self::V1.0
    }

    /// Whether this value is supported.
    pub const fn is_supported(self) -> bool {
        Self::is_supported_raw(self.0)
    }

    /// Validate a raw byte, preserving it on success.
    pub fn parse(raw: u8) -> Result<Self, VersionError> {
        if Self::is_supported_raw(raw) {
            Ok(Self(raw))
        } else {
            Err(VersionError::UnsupportedFrameVersion(raw))
        }
    }
}

impl fmt::Debug for FrameVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FrameVer({})", self.0)
    }
}

/// Protocol major/minor pair carried in `HELLO`/`WELCOME`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ProtoVersion {
    /// Incompatible across majors.
    pub major: u16,
    /// Negotiated as `min(local, remote)`.
    pub minor: u16,
}

impl ProtoVersion {
    /// Version 1.0.
    pub const V1_0: Self = Self { major: 1, minor: 0 };
    /// Version 2.0: the retired PSK wire format.
    ///
    /// It had a 16-entry frame table and a three-flight handshake. Version
    /// 3.0 replaced both; a 2.0 peer is rejected during negotiation.
    pub const V2_0: Self = Self { major: 2, minor: 0 };
    /// Version 3.0: 1-RTT PSK handshake and the 14-entry frame table.
    ///
    /// `HELLO` carries the sealed `AUTH` and `WELCOME` carries the sealed
    /// `ACCEPT`, so the wire format is not compatible with 2.0 even though
    /// both use WCP. The major bump makes the break explicit.
    pub const V3_0: Self = Self { major: 3, minor: 0 };
    /// The version this crate speaks.
    pub const CURRENT: Self = Self::V3_0;
}

/// WCP field-stream version carried in `F_WCP_VER`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WcpVer(u16);

impl WcpVer {
    /// WCP version 1.
    pub const V1: Self = Self(1);
    /// The version this crate writes.
    pub const CURRENT: Self = Self::V1;

    /// Raw value.
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Major version: the low byte, which is the first byte on the wire.
    ///
    /// `F_WCP_VER = 1` (15 §3.2, 21 §3.3, 44 §3.3) therefore means major 1,
    /// minor 0. The "high byte" wording in 44 §6 follows wire order, where
    /// the low byte of a little-endian `u16` is written first.
    pub const fn major(self) -> u16 {
        self.0 & 0x00ff
    }

    /// Minor version: the second wire byte. Newer minors are accepted with
    /// unknown fields ignored.
    pub const fn minor(self) -> u16 {
        self.0 >> 8
    }

    /// Whether a raw value is readable: the major byte must be 1.
    pub const fn is_compatible_raw(raw: u16) -> bool {
        (raw & 0x00ff) == (Self::V1.0 & 0x00ff)
    }

    /// Validate a raw value against the compatibility rule.
    pub fn parse(raw: u16) -> Result<Self, VersionError> {
        if Self::is_compatible_raw(raw) {
            Ok(Self(raw))
        } else {
            Err(VersionError::UnsupportedWcpVersion(raw))
        }
    }
}

impl fmt::Debug for WcpVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WcpVer({}.{})", self.major(), self.minor())
    }
}

/// Capability bits exchanged in `HELLO`/`WELCOME` (`F_CAPS`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Caps(u32);

impl Caps {
    /// ChaCha8-Poly1305. Mandatory in v1; there is no fallback cipher.
    pub const CHACHA8_POLY1305: Self = Self(1 << 0);
    /// zstd compression. Off in v1.
    pub const ZSTD: Self = Self(1 << 1);
    /// Batched broadcast. Off in v1.
    pub const BATCH_BROADCAST: Self = Self(1 << 2);
    /// Per-session keys. Reserved.
    pub const SESSION_KEYS: Self = Self(1 << 3);
    /// PSK handshake support. Mandatory in v3. Reuses bit 5, which carried
    /// `OP_SIGNATURE` in v1.
    pub const PSK_AUTH: Self = Self(1 << 5);

    /// Capabilities without which v3 cannot operate.
    pub const REQUIRED: Self = Self(Self::CHACHA8_POLY1305.0 | Self::PSK_AUTH.0);

    /// No bits set.
    pub const EMPTY: Self = Self(0);

    /// Raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Wrap raw bits without validation.
    pub const fn from_bits(raw: u32) -> Self {
        Self(raw)
    }

    /// Whether every bit of `other` is present.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Set union.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Set intersection; this is the negotiated capability set.
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Remove every bit of `other`.
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Whether no bit is set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Required bits missing from this set.
    pub const fn missing_required(self) -> Self {
        Self(Self::REQUIRED.0 & !self.0)
    }
}

impl fmt::Debug for Caps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Caps(0x{:08x})", self.0)
    }
}

impl fmt::Display for Caps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut sep = |f: &mut fmt::Formatter<'_>| -> fmt::Result {
            if first {
                first = false;
                Ok(())
            } else {
                f.write_str("|")
            }
        };
        if self.contains(Self::CHACHA8_POLY1305) {
            sep(f)?;
            f.write_str("CHACHA8_POLY1305")?;
        }
        if self.contains(Self::ZSTD) {
            sep(f)?;
            f.write_str("ZSTD")?;
        }
        if self.contains(Self::BATCH_BROADCAST) {
            sep(f)?;
            f.write_str("BATCH_BROADCAST")?;
        }
        if self.contains(Self::SESSION_KEYS) {
            sep(f)?;
            f.write_str("SESSION_KEYS")?;
        }
        if self.contains(Self::PSK_AUTH) {
            sep(f)?;
            f.write_str("PSK_AUTH")?;
        }
        let unknown = self
            .without(Self::REQUIRED)
            .without(Self::ZSTD)
            .without(Self::BATCH_BROADCAST)
            .without(Self::SESSION_KEYS);
        if !unknown.is_empty() {
            sep(f)?;
            write!(f, "0x{:08x}", unknown.0)?;
        }
        Ok(())
    }
}

/// Result of a successful negotiation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Negotiated {
    /// Agreed protocol version; `minor` is the lower of the two inputs.
    pub proto: ProtoVersion,
    /// Capability intersection.
    pub caps: Caps,
}

/// A version or capability failure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VersionError {
    /// Frame version byte is not supported.
    UnsupportedFrameVersion(u8),
    /// Protocol majors differ; no compatible mode exists.
    MajorMismatch {
        /// Local major.
        local: u16,
        /// Remote major.
        remote: u16,
    },
    /// A mandatory capability is missing after intersection.
    MissingCapability(Caps),
    /// WCP high byte is not 1.
    UnsupportedWcpVersion(u16),
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFrameVersion(v) => {
                write!(f, "unsupported frame version {v}")
            }
            Self::MajorMismatch { local, remote } => {
                write!(f, "protocol major mismatch: local {local}, remote {remote}")
            }
            Self::MissingCapability(caps) => {
                write!(f, "missing mandatory capability: {caps}")
            }
            Self::UnsupportedWcpVersion(v) => {
                write!(f, "unsupported WCP version 0x{v:04x}")
            }
        }
    }
}

impl std::error::Error for VersionError {}

/// Negotiate protocol version and capabilities.
///
/// Rules (44 §6): majors must match, the minor is the lower of the two, caps
/// are intersected, and both [`Caps::CHACHA8_POLY1305`] and
/// [`Caps::PSK_AUTH`] must survive the intersection. There is no
/// unencrypted, unauthenticated or older-wire compatibility mode in v3.
pub fn negotiate(
    local: ProtoVersion,
    remote: ProtoVersion,
    local_caps: Caps,
    remote_caps: Caps,
) -> Result<Negotiated, VersionError> {
    if local.major != remote.major {
        return Err(VersionError::MajorMismatch {
            local: local.major,
            remote: remote.major,
        });
    }
    let caps = local_caps.intersect(remote_caps);
    let missing = caps.missing_required();
    if !missing.is_empty() {
        return Err(VersionError::MissingCapability(missing));
    }
    Ok(Negotiated {
        proto: ProtoVersion {
            major: local.major,
            minor: local.minor.min(remote.minor),
        },
        caps,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn frame_version_only_accepts_v1() {
        assert!(FrameVer::is_supported_raw(1));
        assert!(!FrameVer::is_supported_raw(0));
        assert!(!FrameVer::is_supported_raw(2));
        assert_eq!(FrameVer::parse(1), Ok(FrameVer::V1));
        assert_eq!(
            FrameVer::parse(2),
            Err(VersionError::UnsupportedFrameVersion(2))
        );
        assert_eq!(FrameVer::CURRENT.get(), 1);
    }

    #[test]
    fn wcp_accepts_newer_minor_and_rejects_other_major() {
        // v1 = 0x0001: major in the first wire byte, minor in the second.
        assert!(WcpVer::is_compatible_raw(0x0001));
        assert!(WcpVer::is_compatible_raw(0x0101));
        assert!(WcpVer::is_compatible_raw(0xff01));
        assert!(!WcpVer::is_compatible_raw(0x0002));
        assert!(!WcpVer::is_compatible_raw(0x0000));
        assert_eq!(WcpVer::parse(0x0201), Ok(WcpVer(0x0201)));
        assert_eq!(
            WcpVer::parse(0x0002),
            Err(VersionError::UnsupportedWcpVersion(0x0002))
        );
        assert_eq!(WcpVer::parse(0x0201).unwrap().minor(), 2);
        assert_eq!(WcpVer::parse(0x0201).unwrap().major(), 1);
    }

    #[test]
    fn negotiate_takes_lower_minor_and_capability_intersection() {
        let local = ProtoVersion { major: 3, minor: 5 };
        let remote = ProtoVersion { major: 3, minor: 2 };
        let caps = Caps::REQUIRED
            .union(Caps::ZSTD)
            .union(Caps::BATCH_BROADCAST);
        let got = negotiate(local, remote, caps, Caps::REQUIRED.union(Caps::ZSTD))
            .expect("negotiation succeeds");
        assert_eq!(got.proto, ProtoVersion { major: 3, minor: 2 });
        assert_eq!(got.caps, Caps::REQUIRED.union(Caps::ZSTD));
        assert!(!got.caps.contains(Caps::BATCH_BROADCAST));
    }

    #[test]
    fn negotiate_rejects_major_mismatch() {
        let err = negotiate(
            ProtoVersion::V3_0,
            ProtoVersion::V2_0,
            Caps::REQUIRED,
            Caps::REQUIRED,
        )
        .expect_err("major mismatch must fail");
        assert_eq!(
            err,
            VersionError::MajorMismatch {
                local: 3,
                remote: 2
            }
        );
    }

    #[test]
    fn negotiate_requires_cipher_and_psk_auth() {
        let err = negotiate(
            ProtoVersion::CURRENT,
            ProtoVersion::CURRENT,
            Caps::REQUIRED.without(Caps::PSK_AUTH),
            Caps::REQUIRED,
        )
        .expect_err("missing PSK capability must fail");
        assert_eq!(err, VersionError::MissingCapability(Caps::PSK_AUTH));

        let err = negotiate(
            ProtoVersion::CURRENT,
            ProtoVersion::CURRENT,
            Caps::ZSTD,
            Caps::REQUIRED,
        )
        .expect_err("missing cipher must fail");
        assert!(matches!(err, VersionError::MissingCapability(_)));
    }

    #[test]
    fn caps_display_lists_names() {
        let caps = Caps::REQUIRED.union(Caps::ZSTD);
        let text = caps.to_string();
        assert!(text.contains("CHACHA8_POLY1305"));
        assert!(text.contains("PSK_AUTH"));
        assert!(text.contains("ZSTD"));
        assert!(!text.contains("BATCH_BROADCAST"));
    }

    #[test]
    fn proto_current_is_major_three_and_rejects_older_wire() {
        assert_eq!(ProtoVersion::CURRENT.major, 3);
        assert_eq!(ProtoVersion::CURRENT.minor, 0);
        assert_eq!(ProtoVersion::CURRENT, ProtoVersion::V3_0);
        assert_eq!(ProtoVersion::V2_0, ProtoVersion { major: 2, minor: 0 });

        let err = negotiate(
            ProtoVersion::CURRENT,
            ProtoVersion::V2_0,
            Caps::REQUIRED,
            Caps::REQUIRED,
        )
        .expect_err("the v2 wire format is not compatible with v3");
        assert_eq!(
            err,
            VersionError::MajorMismatch {
                local: 3,
                remote: 2
            }
        );

        let err = negotiate(
            ProtoVersion::CURRENT,
            ProtoVersion::V1_0,
            Caps::REQUIRED,
            Caps::REQUIRED,
        )
        .expect_err("v1 is not compatible with v3");
        assert_eq!(
            err,
            VersionError::MajorMismatch {
                local: 3,
                remote: 1
            }
        );
    }

    #[test]
    fn psk_auth_reuses_bit_five() {
        assert_eq!(Caps::PSK_AUTH.bits(), 1 << 5);
        assert_eq!(Caps::PSK_AUTH.bits(), 0x20);
        assert!(Caps::REQUIRED.contains(Caps::PSK_AUTH));
        assert_eq!(Caps::REQUIRED, Caps::CHACHA8_POLY1305.union(Caps::PSK_AUTH));
    }
}
