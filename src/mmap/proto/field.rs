//! Tagged field stream and list encoding.
//!
//! ```text
//! field  = tag u8 | len u32 | value[len]
//! list   = count u32 | (record_len u32 | record)*
//! record = field*
//! ```
//!
//! All integers are little-endian. The decoder is strict:
//!
//! * a duplicate tag is an error, never "last one wins";
//! * a field the message does not consume is an unknown tag, never ignored;
//! * a width, UTF-8 or NUL violation is an error, never truncated;
//! * a list count above the caller's cap is refused before allocation.

use super::error::ProtoError;
use super::tag::MAX_TAG;

/// Largest field count in one record.
pub const MAX_FIELDS: usize = 64;

/// Builds a field stream.
#[derive(Clone, Debug, Default)]
pub struct FieldWriter {
    buf: Vec<u8>,
}

impl FieldWriter {
    /// An empty stream.
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty stream with reserved capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    /// Number of bytes written.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing was written.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Consume the writer.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Append one raw field.
    ///
    /// # Errors
    ///
    /// [`ProtoError::UnknownTag`] for tag 0 or a tag above [`MAX_TAG`],
    /// [`ProtoError::ValueOutOfRange`] when the value cannot fit `u32`.
    pub fn raw(&mut self, tag: u8, value: &[u8]) -> Result<(), ProtoError> {
        if tag == 0 || tag > MAX_TAG {
            return Err(ProtoError::UnknownTag(tag));
        }
        let len = u32::try_from(value.len()).map_err(|_| ProtoError::ValueOutOfRange {
            tag,
            value: value.len() as u64,
            max: u64::from(u32::MAX),
        })?;
        self.buf.push(tag);
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(value);
        Ok(())
    }

    /// Append a `u8` field.
    pub fn u8(&mut self, tag: u8, value: u8) -> Result<(), ProtoError> {
        self.raw(tag, &[value])
    }

    /// Append a `u16` field.
    pub fn u16(&mut self, tag: u8, value: u16) -> Result<(), ProtoError> {
        self.raw(tag, &value.to_le_bytes())
    }

    /// Append a `u32` field.
    pub fn u32(&mut self, tag: u8, value: u32) -> Result<(), ProtoError> {
        self.raw(tag, &value.to_le_bytes())
    }

    /// Append a `u64` field.
    pub fn u64(&mut self, tag: u8, value: u64) -> Result<(), ProtoError> {
        self.raw(tag, &value.to_le_bytes())
    }

    /// Append a fixed 16- or 32-byte value.
    pub fn array<const N: usize>(&mut self, tag: u8, value: &[u8; N]) -> Result<(), ProtoError> {
        self.raw(tag, value)
    }

    /// Append a UTF-8 string with no NUL.
    ///
    /// # Errors
    ///
    /// [`ProtoError::NulInString`].
    pub fn string(&mut self, tag: u8, value: &str) -> Result<(), ProtoError> {
        if value.as_bytes().contains(&0) {
            return Err(ProtoError::NulInString { tag });
        }
        self.raw(tag, value.as_bytes())
    }

    /// Append a nested field stream.
    ///
    /// # Errors
    ///
    /// Propagates the closure's error; nothing is written on failure.
    pub fn nested(
        &mut self,
        tag: u8,
        build: impl FnOnce(&mut FieldWriter) -> Result<(), ProtoError>,
    ) -> Result<(), ProtoError> {
        let mut inner = FieldWriter::new();
        build(&mut inner)?;
        self.raw(tag, &inner.buf)
    }

    /// Append a list field.
    ///
    /// # Errors
    ///
    /// [`ProtoError::TooManyRecords`] when `records.len() > cap`,
    /// [`ProtoError::ValueOutOfRange`] when a record exceeds `u32`.
    pub fn list(&mut self, tag: u8, cap: u32, records: &[Vec<u8>]) -> Result<(), ProtoError> {
        let count = u32::try_from(records.len()).map_err(|_| ProtoError::ValueOutOfRange {
            tag,
            value: records.len() as u64,
            max: u64::from(u32::MAX),
        })?;
        if count > cap {
            return Err(ProtoError::TooManyRecords { tag, count, cap });
        }
        let mut value = Vec::with_capacity(4 + records.iter().map(|r| 4 + r.len()).sum::<usize>());
        value.extend_from_slice(&count.to_le_bytes());
        for record in records {
            let len = u32::try_from(record.len()).map_err(|_| ProtoError::ValueOutOfRange {
                tag,
                value: record.len() as u64,
                max: u64::from(u32::MAX),
            })?;
            value.extend_from_slice(&len.to_le_bytes());
            value.extend_from_slice(record);
        }
        self.raw(tag, &value)
    }
}

/// A parsed field stream, consumed tag by tag.
#[derive(Debug)]
pub struct Fields<'a> {
    entries: Vec<(u8, &'a [u8])>,
    consumed: Vec<u8>,
    len: usize,
}

impl<'a> Fields<'a> {
    /// Parse a complete field stream.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Truncated`], [`ProtoError::DuplicateTag`] or
    /// [`ProtoError::TooManyFields`].
    pub fn parse(bytes: &'a [u8], max_fields: usize) -> Result<Self, ProtoError> {
        let mut entries = Vec::new();
        let mut pos = 0usize;
        while pos < bytes.len() {
            if bytes.len() - pos < 5 {
                return Err(ProtoError::Truncated {
                    need: 5,
                    got: bytes.len() - pos,
                });
            }
            let tag = bytes[pos];
            let len = u32::from_le_bytes([
                bytes[pos + 1],
                bytes[pos + 2],
                bytes[pos + 3],
                bytes[pos + 4],
            ]) as usize;
            pos += 5;
            let end = pos.checked_add(len).ok_or(ProtoError::Truncated {
                need: usize::MAX,
                got: bytes.len() - pos,
            })?;
            if end > bytes.len() {
                return Err(ProtoError::Truncated {
                    need: len,
                    got: bytes.len() - pos,
                });
            }
            if entries.len() >= max_fields {
                return Err(ProtoError::TooManyFields(max_fields));
            }
            if entries.iter().any(|(seen, _)| *seen == tag) {
                return Err(ProtoError::DuplicateTag(tag));
            }
            entries.push((tag, &bytes[pos..end]));
            pos = end;
        }
        Ok(Self {
            entries,
            consumed: Vec::new(),
            len: bytes.len(),
        })
    }

    /// Total bytes parsed.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the stream carried no field.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Take one field, marking it consumed.
    pub fn take(&mut self, tag: u8) -> Option<&'a [u8]> {
        if self.consumed.contains(&tag) {
            return None;
        }
        let value = self
            .entries
            .iter()
            .find(|(seen, _)| *seen == tag)
            .map(|(_, value)| *value)?;
        self.consumed.push(tag);
        Some(value)
    }

    /// Whether `tag` was already taken.
    pub fn is_consumed(&self, tag: u8) -> bool {
        self.consumed.contains(&tag)
    }

    /// Number of consumed fields.
    pub fn consumed_len(&self) -> usize {
        self.consumed.len()
    }

    /// Number of fields in the stream.
    pub fn field_count(&self) -> usize {
        self.entries.len()
    }

    /// Take a field by tag, allowing repeated reads.
    ///
    /// This is only for callers that need to inspect a value twice; the
    /// regular path is [`Fields::take`], which enforces single use.
    pub fn peek(&self, tag: u8) -> Option<&'a [u8]> {
        self.entries
            .iter()
            .find(|(seen, _)| *seen == tag)
            .map(|(_, value)| *value)
    }

    /// Take a required field.
    ///
    /// # Errors
    ///
    /// [`ProtoError::MissingField`].
    pub fn req(&mut self, tag: u8) -> Result<&'a [u8], ProtoError> {
        self.take(tag).ok_or(ProtoError::MissingField(tag))
    }

    /// Take an optional field.
    pub fn opt(&mut self, tag: u8) -> Option<&'a [u8]> {
        self.take(tag)
    }

    /// Read a required `u8`.
    pub fn u8(&mut self, tag: u8) -> Result<u8, ProtoError> {
        let value = self.req(tag)?;
        match value {
            [byte] => Ok(*byte),
            other => Err(ProtoError::BadFieldLen {
                tag,
                expected: "u8",
                got: other.len(),
            }),
        }
    }

    /// Read an optional `u8`.
    pub fn opt_u8(&mut self, tag: u8) -> Result<Option<u8>, ProtoError> {
        match self.opt(tag) {
            None => Ok(None),
            Some([byte]) => Ok(Some(*byte)),
            Some(other) => Err(ProtoError::BadFieldLen {
                tag,
                expected: "u8",
                got: other.len(),
            }),
        }
    }

    /// Read a required `u16`.
    pub fn u16(&mut self, tag: u8) -> Result<u16, ProtoError> {
        let value = self.req(tag)?;
        let bytes: [u8; 2] = value.try_into().map_err(|_| ProtoError::BadFieldLen {
            tag,
            expected: "u16",
            got: value.len(),
        })?;
        Ok(u16::from_le_bytes(bytes))
    }

    /// Read a required `u32`.
    pub fn u32(&mut self, tag: u8) -> Result<u32, ProtoError> {
        let value = self.req(tag)?;
        let bytes: [u8; 4] = value.try_into().map_err(|_| ProtoError::BadFieldLen {
            tag,
            expected: "u32",
            got: value.len(),
        })?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Read an optional `u32`.
    pub fn opt_u32(&mut self, tag: u8) -> Result<Option<u32>, ProtoError> {
        match self.opt(tag) {
            None => Ok(None),
            Some(value) => {
                let bytes: [u8; 4] = value.try_into().map_err(|_| ProtoError::BadFieldLen {
                    tag,
                    expected: "u32",
                    got: value.len(),
                })?;
                Ok(Some(u32::from_le_bytes(bytes)))
            }
        }
    }

    /// Read a required `u64`.
    pub fn u64(&mut self, tag: u8) -> Result<u64, ProtoError> {
        let value = self.req(tag)?;
        let bytes: [u8; 8] = value.try_into().map_err(|_| ProtoError::BadFieldLen {
            tag,
            expected: "u64",
            got: value.len(),
        })?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Read an optional `u64`.
    pub fn opt_u64(&mut self, tag: u8) -> Result<Option<u64>, ProtoError> {
        match self.opt(tag) {
            None => Ok(None),
            Some(value) => {
                let bytes: [u8; 8] = value.try_into().map_err(|_| ProtoError::BadFieldLen {
                    tag,
                    expected: "u64",
                    got: value.len(),
                })?;
                Ok(Some(u64::from_le_bytes(bytes)))
            }
        }
    }

    /// Read a required fixed-size value.
    pub fn array<const N: usize>(&mut self, tag: u8) -> Result<[u8; N], ProtoError> {
        let value = self.req(tag)?;
        value.try_into().map_err(|_| ProtoError::BadFieldLen {
            tag,
            expected: "fixed array",
            got: value.len(),
        })
    }

    /// Read an optional fixed-size value.
    pub fn opt_array<const N: usize>(&mut self, tag: u8) -> Result<Option<[u8; N]>, ProtoError> {
        match self.opt(tag) {
            None => Ok(None),
            Some(value) => Ok(Some(value.try_into().map_err(|_| {
                ProtoError::BadFieldLen {
                    tag,
                    expected: "fixed array",
                    got: value.len(),
                }
            })?)),
        }
    }

    /// Read a required UTF-8 string with no NUL and at most `max` bytes.
    pub fn string(&mut self, tag: u8, max: usize) -> Result<&'a str, ProtoError> {
        let value = self.req(tag)?;
        decode_string(tag, value, max)
    }

    /// Read an optional UTF-8 string with no NUL and at most `max` bytes.
    pub fn opt_string(&mut self, tag: u8, max: usize) -> Result<Option<&'a str>, ProtoError> {
        match self.opt(tag) {
            None => Ok(None),
            Some(value) => Ok(Some(decode_string(tag, value, max)?)),
        }
    }

    /// Read a required list and return each record's bytes.
    pub fn list(&mut self, tag: u8, cap: u32) -> Result<Vec<&'a [u8]>, ProtoError> {
        let value = self.req(tag)?;
        parse_list(value, tag, cap)
    }

    /// Read an optional list.
    pub fn opt_list(&mut self, tag: u8, cap: u32) -> Result<Vec<&'a [u8]>, ProtoError> {
        match self.opt(tag) {
            None => Ok(Vec::new()),
            Some(value) => parse_list(value, tag, cap),
        }
    }

    /// Read a required nested record.
    pub fn nested(&mut self, tag: u8) -> Result<Fields<'a>, ProtoError> {
        let value = self.req(tag)?;
        Fields::parse(value, MAX_FIELDS)
    }

    /// Read an optional nested record.
    pub fn opt_nested(&mut self, tag: u8) -> Result<Option<Fields<'a>>, ProtoError> {
        match self.opt(tag) {
            None => Ok(None),
            Some(value) => Ok(Some(Fields::parse(value, MAX_FIELDS)?)),
        }
    }

    /// Assert that every field was consumed.
    ///
    /// # Errors
    ///
    /// [`ProtoError::UnknownTag`] naming the first unconsumed tag.
    pub fn finish(self) -> Result<(), ProtoError> {
        if let Some((tag, _)) = self
            .entries
            .iter()
            .find(|(tag, _)| !self.consumed.contains(tag))
        {
            return Err(ProtoError::UnknownTag(*tag));
        }
        Ok(())
    }
}

fn decode_string(tag: u8, value: &[u8], max: usize) -> Result<&str, ProtoError> {
    if value.len() > max {
        return Err(ProtoError::ValueOutOfRange {
            tag,
            value: value.len() as u64,
            max: max as u64,
        });
    }
    if value.contains(&0) {
        return Err(ProtoError::NulInString { tag });
    }
    std::str::from_utf8(value).map_err(|_| ProtoError::BadUtf8 { tag })
}

/// Parse a list value into record slices.
///
/// # Errors
///
/// [`ProtoError::Truncated`], [`ProtoError::TooManyRecords`] or
/// [`ProtoError::ValueOutOfRange`].
pub fn parse_list(value: &[u8], tag: u8, cap: u32) -> Result<Vec<&[u8]>, ProtoError> {
    if value.len() < 4 {
        return Err(ProtoError::Truncated {
            need: 4,
            got: value.len(),
        });
    }
    let count = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
    if count > cap {
        return Err(ProtoError::TooManyRecords { tag, count, cap });
    }
    let mut records = Vec::with_capacity(count as usize);
    let mut pos = 4usize;
    for _ in 0..count {
        if value.len() - pos < 4 {
            return Err(ProtoError::Truncated {
                need: 4,
                got: value.len() - pos,
            });
        }
        let len = u32::from_le_bytes([value[pos], value[pos + 1], value[pos + 2], value[pos + 3]])
            as usize;
        pos += 4;
        let end = pos.checked_add(len).ok_or(ProtoError::Truncated {
            need: usize::MAX,
            got: value.len() - pos,
        })?;
        if end > value.len() {
            return Err(ProtoError::Truncated {
                need: len,
                got: value.len() - pos,
            });
        }
        records.push(&value[pos..end]);
        pos = end;
    }
    if pos != value.len() {
        return Err(ProtoError::TrailingBytes(value.len() - pos));
    }
    Ok(records)
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn scalar_fields_round_trip() {
        let mut writer = FieldWriter::new();
        writer.u8(0x01, 7).unwrap();
        writer.u16(0x02, 0x1234).unwrap();
        writer.u32(0x03, 0xDEAD_BEEF).unwrap();
        writer.u64(0x04, 0x0102_0304_0506_0708).unwrap();
        writer.string(0x05, "hello").unwrap();
        writer.array(0x06, &[0xAA; 16]).unwrap();
        let bytes = writer.into_bytes();

        let mut fields = Fields::parse(&bytes, MAX_FIELDS).unwrap();
        assert_eq!(fields.u8(0x01).unwrap(), 7);
        assert_eq!(fields.u16(0x02).unwrap(), 0x1234);
        assert_eq!(fields.u32(0x03).unwrap(), 0xDEAD_BEEF);
        assert_eq!(fields.u64(0x04).unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(fields.string(0x05, 16).unwrap(), "hello");
        assert_eq!(fields.array::<16>(0x06).unwrap(), [0xAA; 16]);
        fields.finish().unwrap();
    }

    #[test]
    fn duplicate_tag_is_rejected() {
        let mut writer = FieldWriter::new();
        writer.u8(0x01, 1).unwrap();
        writer.u8(0x01, 2).unwrap();
        let bytes = writer.into_bytes();
        assert!(matches!(
            Fields::parse(&bytes, MAX_FIELDS),
            Err(ProtoError::DuplicateTag(0x01))
        ));
    }

    #[test]
    fn unknown_tag_is_rejected_at_finish() {
        let mut writer = FieldWriter::new();
        writer.u8(0x01, 1).unwrap();
        writer.u8(0x02, 2).unwrap();
        let bytes = writer.into_bytes();
        let mut fields = Fields::parse(&bytes, MAX_FIELDS).unwrap();
        assert_eq!(fields.u8(0x01).unwrap(), 1);
        assert!(matches!(fields.finish(), Err(ProtoError::UnknownTag(0x02))));
    }

    #[test]
    fn missing_field_is_reported() {
        let mut writer = FieldWriter::new();
        writer.u8(0x01, 1).unwrap();
        let bytes = writer.into_bytes();
        let mut fields = Fields::parse(&bytes, MAX_FIELDS).unwrap();
        assert!(matches!(
            fields.u8(0x02),
            Err(ProtoError::MissingField(0x02))
        ));
    }

    #[test]
    fn width_mismatch_is_rejected() {
        let mut writer = FieldWriter::new();
        writer.u16(0x01, 1).unwrap();
        let bytes = writer.into_bytes();
        let mut fields = Fields::parse(&bytes, MAX_FIELDS).unwrap();
        assert!(matches!(
            fields.u8(0x01),
            Err(ProtoError::BadFieldLen { tag: 0x01, .. })
        ));
    }

    #[test]
    fn truncation_at_every_boundary_is_rejected() {
        let mut writer = FieldWriter::new();
        writer.string(0x01, "abc").unwrap();
        let bytes = writer.into_bytes();
        assert!(Fields::parse(&[], MAX_FIELDS).is_ok());
        for cut in 1..bytes.len() {
            assert!(
                Fields::parse(&bytes[..cut], MAX_FIELDS).is_err(),
                "prefix of {cut} bytes must not parse"
            );
        }
    }

    #[test]
    fn lists_round_trip_and_enforce_the_cap() {
        let records = vec![vec![1, 2, 3], vec![], vec![9; 40]];
        let mut writer = FieldWriter::new();
        writer.list(0x11, 3, &records).unwrap();
        let bytes = writer.into_bytes();
        let mut fields = Fields::parse(&bytes, MAX_FIELDS).unwrap();
        let decoded = fields.list(0x11, 3).unwrap();
        assert_eq!(decoded, vec![&[1, 2, 3][..], &[][..], &[9; 40][..]]);
        fields.finish().unwrap();

        let mut writer = FieldWriter::new();
        assert!(matches!(
            writer.list(0x11, 2, &records),
            Err(ProtoError::TooManyRecords {
                tag: 0x11,
                count: 3,
                cap: 2
            })
        ));
    }

    #[test]
    fn list_truncation_and_trailing_bytes_are_rejected() {
        let mut value = Vec::new();
        value.extend_from_slice(&2u32.to_le_bytes());
        value.extend_from_slice(&1u32.to_le_bytes());
        value.push(0xAA);
        assert!(matches!(
            parse_list(&value, 0x11, 2),
            Err(ProtoError::Truncated { .. })
        ));

        let mut value = Vec::new();
        value.extend_from_slice(&0u32.to_le_bytes());
        value.push(0xAA);
        assert!(matches!(
            parse_list(&value, 0x11, 2),
            Err(ProtoError::TrailingBytes(1))
        ));
    }

    #[test]
    fn nested_records_are_isolated() {
        let mut writer = FieldWriter::new();
        writer
            .nested(0x37, |inner| {
                inner.u32(0x01, 100).unwrap();
                inner.u32(0x02, 200)
            })
            .unwrap();
        let bytes = writer.into_bytes();
        let mut fields = Fields::parse(&bytes, MAX_FIELDS).unwrap();
        let mut nested = fields.nested(0x37).unwrap();
        assert_eq!(nested.u32(0x01).unwrap(), 100);
        assert_eq!(nested.u32(0x02).unwrap(), 200);
        nested.finish().unwrap();
        fields.finish().unwrap();
    }

    #[test]
    fn nul_and_bad_utf8_are_rejected() {
        let mut writer = FieldWriter::new();
        assert!(matches!(
            writer.string(0x01, "a\0b"),
            Err(ProtoError::NulInString { tag: 0x01 })
        ));

        let mut writer = FieldWriter::new();
        writer.raw(0x01, &[0xFF, 0xFE]).unwrap();
        let bytes = writer.into_bytes();
        let mut fields = Fields::parse(&bytes, MAX_FIELDS).unwrap();
        assert!(matches!(
            fields.string(0x01, 16),
            Err(ProtoError::BadUtf8 { tag: 0x01 })
        ));
    }

    #[test]
    fn string_cap_is_enforced() {
        let mut writer = FieldWriter::new();
        writer.string(0x01, "abcdef").unwrap();
        let bytes = writer.into_bytes();
        let mut fields = Fields::parse(&bytes, MAX_FIELDS).unwrap();
        assert!(matches!(
            fields.string(0x01, 5),
            Err(ProtoError::ValueOutOfRange {
                tag: 0x01,
                value: 6,
                max: 5
            })
        ));
    }

    #[test]
    fn field_count_is_bounded() {
        let mut writer = FieldWriter::new();
        for tag in 1..=3u8 {
            writer.u8(tag, tag).unwrap();
        }
        let bytes = writer.into_bytes();
        assert!(matches!(
            Fields::parse(&bytes, 2),
            Err(ProtoError::TooManyFields(2))
        ));
    }

    #[test]
    fn tag_zero_and_above_max_are_rejected() {
        let mut writer = FieldWriter::new();
        assert!(matches!(writer.u8(0, 0), Err(ProtoError::UnknownTag(0))));
        assert!(matches!(
            writer.u8(super::super::tag::REASON + 1, 0),
            Err(ProtoError::UnknownTag(_))
        ));
    }
}
