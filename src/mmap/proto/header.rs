//! The 24-byte SMM1 header.
//!
//! ```text
//! off width field
//!   0     4 magic = "SMM1"
//!   4     1 ver = 1
//!   5     1 kind
//!   6     2 flags
//!   8     4 meta_len
//!  12     8 data_len
//!  20     4 reserved = 0
//! ```
//!
//! All integers are little-endian. `meta_len` bounds the tagged field stream;
//! `data_len` bounds the payload that follows it. Neither is trusted: both are
//! checked against [`Limits`] before a byte is allocated.

use super::error::ProtoError;
use super::kind::Kind;
use super::limits::Limits;

/// Header width.
pub const HEADER_LEN: usize = 24;
/// Magic bytes.
pub const MAGIC: [u8; 4] = *b"SMM1";
/// The only supported version.
pub const VERSION: u8 = 1;
/// No flags are defined in version 1.
pub const FLAGS_NONE: u16 = 0;

/// A decoded header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Format version; always [`VERSION`] after a successful decode.
    pub ver: u8,
    /// Message kind.
    pub kind: Kind,
    /// Reserved for future use; must be [`FLAGS_NONE`].
    pub flags: u16,
    /// Tagged meta length.
    pub meta_len: u32,
    /// Payload length.
    pub data_len: u64,
    /// Must be zero.
    pub reserved: u32,
}

impl Header {
    /// Build a version-1 header with no flags and a zero reserved word.
    ///
    /// # Errors
    ///
    /// [`ProtoError::MetaTooLarge`] or [`ProtoError::DataTooLarge`] when the
    /// declared lengths exceed `limits`.
    pub fn new(
        kind: Kind,
        meta_len: u32,
        data_len: u64,
        limits: &Limits,
    ) -> Result<Self, ProtoError> {
        limits.check_meta(u64::from(meta_len))?;
        limits.check_data(data_len)?;
        Ok(Self {
            ver: VERSION,
            kind,
            flags: FLAGS_NONE,
            meta_len,
            data_len,
            reserved: 0,
        })
    }

    /// Encode exactly 24 bytes.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..4].copy_from_slice(&MAGIC);
        out[4] = self.ver;
        out[5] = self.kind.as_u8();
        out[6..8].copy_from_slice(&self.flags.to_le_bytes());
        out[8..12].copy_from_slice(&self.meta_len.to_le_bytes());
        out[12..20].copy_from_slice(&self.data_len.to_le_bytes());
        out[20..24].copy_from_slice(&self.reserved.to_le_bytes());
        out
    }

    /// Decode the first 24 bytes of `bytes`.
    ///
    /// This checks magic, version, kind, flags and the reserved word, but not
    /// the length caps; call [`Header::check_limits`] for those. Use
    /// [`Header::decode_with_limits`] for both.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Truncated`], [`ProtoError::BadMagic`],
    /// [`ProtoError::UnsupportedVersion`], [`ProtoError::UnknownKind`],
    /// [`ProtoError::ReservedFlags`] or [`ProtoError::NonZeroReserved`].
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() < HEADER_LEN {
            return Err(ProtoError::Truncated {
                need: HEADER_LEN,
                got: bytes.len(),
            });
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[..4]);
        if magic != MAGIC {
            return Err(ProtoError::BadMagic(magic));
        }
        let ver = bytes[4];
        if ver != VERSION {
            return Err(ProtoError::UnsupportedVersion(ver));
        }
        let kind = Kind::from_u8(bytes[5])?;
        let flags = u16::from_le_bytes([bytes[6], bytes[7]]);
        if flags != FLAGS_NONE {
            return Err(ProtoError::ReservedFlags(flags));
        }
        let meta_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let data_len = u64::from_le_bytes([
            bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19],
        ]);
        let reserved = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        if reserved != 0 {
            return Err(ProtoError::NonZeroReserved(reserved));
        }
        Ok(Self {
            ver,
            kind,
            flags,
            meta_len,
            data_len,
            reserved,
        })
    }

    /// Decode and enforce the length caps.
    ///
    /// # Errors
    ///
    /// Any [`Header::decode`] error, plus [`ProtoError::MetaTooLarge`] or
    /// [`ProtoError::DataTooLarge`].
    pub fn decode_with_limits(bytes: &[u8], limits: &Limits) -> Result<Self, ProtoError> {
        let header = Self::decode(bytes)?;
        header.check_limits(limits)?;
        Ok(header)
    }

    /// Enforce the length caps on an already decoded header.
    ///
    /// # Errors
    ///
    /// [`ProtoError::MetaTooLarge`] or [`ProtoError::DataTooLarge`].
    pub fn check_limits(&self, limits: &Limits) -> Result<(), ProtoError> {
        limits.check_meta(u64::from(self.meta_len))?;
        limits.check_data(self.data_len)
    }

    /// Total wire width of header, meta and payload.
    ///
    /// # Errors
    ///
    /// [`ProtoError::DataTooLarge`] on `u64` overflow.
    pub fn frame_len(&self) -> Result<u64, ProtoError> {
        let total = u64::from(self.meta_len)
            .checked_add(self.data_len)
            .and_then(|n| n.checked_add(HEADER_LEN as u64))
            .ok_or(ProtoError::DataTooLarge {
                len: u64::MAX,
                cap: u64::from(self.meta_len),
            })?;
        Ok(total)
    }
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn header_round_trips() {
        let limits = Limits::new();
        let header = Header::new(Kind::UploadCommit, 17, 1 << 30, &limits).unwrap();
        let bytes = header.encode();
        assert_eq!(bytes.len(), 24);
        assert_eq!(&bytes[..4], b"SMM1");
        assert_eq!(bytes[4], 1);
        assert_eq!(bytes[5], 0x16);
        assert_eq!(Header::decode(&bytes).unwrap(), header);
        assert_eq!(header.frame_len().unwrap(), 24 + 17 + (1 << 30));
    }

    #[test]
    fn bad_magic_version_flags_and_reserved_are_rejected() {
        let limits = Limits::new();
        let good = Header::new(Kind::Hello, 0, 0, &limits).unwrap().encode();

        let mut bad = good;
        bad[0] = b'X';
        assert!(matches!(Header::decode(&bad), Err(ProtoError::BadMagic(_))));

        let mut bad = good;
        bad[4] = 2;
        assert!(matches!(
            Header::decode(&bad),
            Err(ProtoError::UnsupportedVersion(2))
        ));

        let mut bad = good;
        bad[5] = 0x42;
        assert!(matches!(
            Header::decode(&bad),
            Err(ProtoError::UnknownKind(0x42))
        ));

        let mut bad = good;
        bad[6] = 1;
        assert!(matches!(
            Header::decode(&bad),
            Err(ProtoError::ReservedFlags(1))
        ));

        let mut bad = good;
        bad[20] = 1;
        assert!(matches!(
            Header::decode(&bad),
            Err(ProtoError::NonZeroReserved(1))
        ));
    }

    #[test]
    fn short_header_is_truncated() {
        assert!(matches!(
            Header::decode(&[0u8; 23]),
            Err(ProtoError::Truncated { need: 24, got: 23 })
        ));
    }

    #[test]
    fn oversized_lengths_are_rejected_before_allocation() {
        let limits = Limits {
            max_meta_len: 16,
            max_data_len: 32,
            ..Limits::new()
        };
        let mut bytes = Header::new(Kind::Snapshot, 0, 0, &limits).unwrap().encode();
        bytes[8..12].copy_from_slice(&17u32.to_le_bytes());
        assert!(matches!(
            Header::decode_with_limits(&bytes, &limits),
            Err(ProtoError::MetaTooLarge { len: 17, cap: 16 })
        ));

        bytes[8..12].copy_from_slice(&16u32.to_le_bytes());
        bytes[12..20].copy_from_slice(&33u64.to_le_bytes());
        assert!(matches!(
            Header::decode_with_limits(&bytes, &limits),
            Err(ProtoError::DataTooLarge { len: 33, cap: 32 })
        ));
    }
}
