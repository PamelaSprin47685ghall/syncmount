//! Size and count limits for one SMM1 exchange.
//!
//! Limits travel in `WELCOME` and `UPLOAD_PLAN`, but every decoder also has a
//! local [`Limits::default`] so a peer cannot raise its own cap. The numbers
//! below are the design defaults; a server may advertise smaller values, never
//! larger ones (the client intersects).

use super::error::ProtoError;

/// 100,000 direct entries per directory batch.
pub const MAX_ENTRIES: u32 = 100_000;
/// 1,048,576 rsync blocks per file.
pub const MAX_BLOCKS: u32 = 1 << 20;
/// 16 MiB of meta.
pub const MAX_META: u32 = 16 * 1024 * 1024;
/// 64 GiB of payload in one request (the batch cap).
pub const MAX_DATA: u64 = 64 * 1024 * 1024 * 1024;
/// 8 MiB per `FILE_READ` range.
pub const MAX_RANGE: u32 = 8 * 1024 * 1024;
/// 4 GiB per file.
pub const MAX_FILE: u64 = 4 * 1024 * 1024 * 1024;
/// 64 GiB per batch.
pub const MAX_BATCH: u64 = MAX_DATA;

/// Caps for one request or response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum direct entries in a manifest.
    pub max_entries: u32,
    /// Maximum signature blocks in one file.
    pub max_blocks: u32,
    /// Maximum `meta_len`.
    pub max_meta_len: u32,
    /// Maximum `data_len`.
    pub max_data_len: u64,
    /// Maximum `FILE_READ` range.
    pub max_range_len: u32,
    /// Maximum file size.
    pub max_file_size: u64,
    /// Maximum bytes in one batch.
    pub max_batch_bytes: u64,
}

impl Limits {
    /// The design defaults.
    pub const fn new() -> Self {
        Self {
            max_entries: MAX_ENTRIES,
            max_blocks: MAX_BLOCKS,
            max_meta_len: MAX_META,
            max_data_len: MAX_DATA,
            max_range_len: MAX_RANGE,
            max_file_size: MAX_FILE,
            max_batch_bytes: MAX_BATCH,
        }
    }

    /// Reject a nonsensical limit set before it is used.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Inconsistent`] when a zero cap or a cap above the local
    /// default appears.
    pub fn validate(&self) -> Result<(), ProtoError> {
        let local = Self::new();
        if self.max_entries == 0
            || self.max_blocks == 0
            || self.max_meta_len == 0
            || self.max_data_len == 0
            || self.max_range_len == 0
            || self.max_file_size == 0
            || self.max_batch_bytes == 0
        {
            return Err(ProtoError::Inconsistent("zero limit"));
        }
        if self.max_entries > local.max_entries
            || self.max_blocks > local.max_blocks
            || self.max_meta_len > local.max_meta_len
            || self.max_data_len > local.max_data_len
            || self.max_range_len > local.max_range_len
            || self.max_file_size > local.max_file_size
            || self.max_batch_bytes > local.max_batch_bytes
        {
            return Err(ProtoError::Inconsistent("limit above local default"));
        }
        Ok(())
    }

    /// The tighter of two sets, field by field.
    pub const fn intersect(self, other: Self) -> Self {
        Self {
            max_entries: min_u32(self.max_entries, other.max_entries),
            max_blocks: min_u32(self.max_blocks, other.max_blocks),
            max_meta_len: min_u32(self.max_meta_len, other.max_meta_len),
            max_data_len: min_u64(self.max_data_len, other.max_data_len),
            max_range_len: min_u32(self.max_range_len, other.max_range_len),
            max_file_size: min_u64(self.max_file_size, other.max_file_size),
            max_batch_bytes: min_u64(self.max_batch_bytes, other.max_batch_bytes),
        }
    }

    /// Check a declared `meta_len`.
    ///
    /// # Errors
    ///
    /// [`ProtoError::MetaTooLarge`].
    pub fn check_meta(&self, len: u64) -> Result<(), ProtoError> {
        if len > u64::from(self.max_meta_len) {
            return Err(ProtoError::MetaTooLarge {
                len,
                cap: u64::from(self.max_meta_len),
            });
        }
        Ok(())
    }

    /// Check a declared `data_len`.
    ///
    /// # Errors
    ///
    /// [`ProtoError::DataTooLarge`].
    pub fn check_data(&self, len: u64) -> Result<(), ProtoError> {
        if len > self.max_data_len {
            return Err(ProtoError::DataTooLarge {
                len,
                cap: self.max_data_len,
            });
        }
        Ok(())
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::new()
    }
}

const fn min_u32(a: u32, b: u32) -> u32 {
    if a < b { a } else { b }
}

const fn min_u64(a: u64, b: u64) -> u64 {
    if a < b { a } else { b }
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn defaults_are_the_design_numbers() {
        let limits = Limits::new();
        assert_eq!(limits.max_entries, 100_000);
        assert_eq!(limits.max_blocks, 1 << 20);
        assert_eq!(limits.max_meta_len, 16 * 1024 * 1024);
        assert_eq!(limits.max_data_len, 64 * 1024 * 1024 * 1024);
        assert_eq!(limits.max_range_len, 8 * 1024 * 1024);
        assert_eq!(limits.max_file_size, 4 * 1024 * 1024 * 1024);
        assert!(limits.validate().is_ok());
    }

    #[test]
    fn intersection_takes_the_tighter_cap() {
        let a = Limits::new();
        let b = Limits {
            max_entries: 10,
            max_blocks: 20,
            max_meta_len: 30,
            max_data_len: 40,
            max_range_len: 50,
            max_file_size: 60,
            max_batch_bytes: 70,
        };
        assert_eq!(a.intersect(b), b);
        assert_eq!(b.intersect(a), b);
    }

    #[test]
    fn oversized_meta_and_data_are_rejected() {
        let limits = Limits {
            max_meta_len: 4,
            max_data_len: 8,
            ..Limits::new()
        };
        assert!(matches!(
            limits.check_meta(5),
            Err(ProtoError::MetaTooLarge { len: 5, cap: 4 })
        ));
        assert!(matches!(
            limits.check_data(9),
            Err(ProtoError::DataTooLarge { len: 9, cap: 8 })
        ));
        assert!(limits.check_meta(4).is_ok());
        assert!(limits.check_data(8).is_ok());
    }

    #[test]
    fn a_peer_cannot_raise_a_limit() {
        let mut limits = Limits::new();
        limits.max_entries = MAX_ENTRIES + 1;
        assert!(limits.validate().is_err());
    }
}

impl Limits {
    /// Encode as a nested field stream under `tag`.
    ///
    /// # Errors
    ///
    /// Propagates field encoding errors.
    pub(crate) fn encode_into(
        &self,
        writer: &mut super::field::FieldWriter,
        tag: u8,
    ) -> Result<(), ProtoError> {
        self.validate()?;
        writer.nested(tag, |inner| {
            inner.u32(super::tag::LIMIT_MAX_ENTRIES, self.max_entries)?;
            inner.u32(super::tag::LIMIT_MAX_BLOCKS, self.max_blocks)?;
            inner.u32(super::tag::LIMIT_MAX_META_LEN, self.max_meta_len)?;
            inner.u64(super::tag::LIMIT_MAX_DATA_LEN, self.max_data_len)?;
            inner.u32(super::tag::LIMIT_MAX_RANGE_LEN, self.max_range_len)?;
            inner.u64(super::tag::LIMIT_MAX_FILE_SIZE, self.max_file_size)?;
            inner.u64(super::tag::LIMIT_MAX_BATCH_BYTES, self.max_batch_bytes)
        })
    }

    /// Decode a nested field stream.
    ///
    /// # Errors
    ///
    /// Missing or invalid fields, or a set above the local default.
    pub(crate) fn decode_from(mut fields: super::field::Fields<'_>) -> Result<Self, ProtoError> {
        let limits = Self {
            max_entries: fields.u32(super::tag::LIMIT_MAX_ENTRIES)?,
            max_blocks: fields.u32(super::tag::LIMIT_MAX_BLOCKS)?,
            max_meta_len: fields.u32(super::tag::LIMIT_MAX_META_LEN)?,
            max_data_len: fields.u64(super::tag::LIMIT_MAX_DATA_LEN)?,
            max_range_len: fields.u32(super::tag::LIMIT_MAX_RANGE_LEN)?,
            max_file_size: fields.u64(super::tag::LIMIT_MAX_FILE_SIZE)?,
            max_batch_bytes: fields.u64(super::tag::LIMIT_MAX_BATCH_BYTES)?,
        };
        fields.finish()?;
        limits.validate()?;
        Ok(limits)
    }
}
