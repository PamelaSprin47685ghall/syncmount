//! Incremental frame codec.
//!
//! The decoder is **push-based and purely incremental**: it never reads from
//! a socket, never blocks and never allocates from an attacker-controlled
//! length. Bytes arrive through [`FrameDecoder::push`]; complete frames come
//! out through [`FrameDecoder::next_frame`] (borrowed) or
//! [`FrameDecoder::next_frame_owned`] (owned).
//!
//! [`FrameReader`]/[`FrameWriter`] are thin synchronous adapters over
//! `std::io::{Read, Write}`. They exist for golden vectors and unit tests;
//! production transport hands byte streams to the decoder directly.

use std::io::{Read, Write};

use crate::protocol::FRAME_MAX;
use crate::protocol::errors::ProtocolError;
use crate::protocol::frame::{
    CTRL_PREFIX_LEN, Frame, FrameBuf, FrameHeader, HEADER_LEN, Limits, Prefix, ROUTE_PREFIX_LEN,
};
use crate::protocol::version::FrameVer;

/// A frame about to be encoded. All three parts are borrowed so that the
/// encoder performs exactly one copy into its output buffer.
#[derive(Clone, Copy, Debug)]
pub struct FrameRef<'a> {
    /// Header to write.
    pub header: &'a FrameHeader,
    /// Prefix to write.
    pub prefix: &'a Prefix,
    /// Body to write.
    pub body: &'a [u8],
}

impl<'a> FrameRef<'a> {
    /// Borrow the three parts.
    pub const fn new(header: &'a FrameHeader, prefix: &'a Prefix, body: &'a [u8]) -> Self {
        Self {
            header,
            prefix,
            body,
        }
    }

    /// Whole-frame width including the header.
    pub fn encoded_len(&self) -> usize {
        HEADER_LEN + self.prefix.encoded_len() + self.body.len()
    }

    /// Reject any inconsistency before a single byte is written.
    ///
    /// This is the poka-yoke behind INV-01: `len` is derived, never trusted.
    pub fn check(&self) -> Result<(), ProtocolError> {
        if !FrameVer::is_supported_raw(self.header.ver) {
            return Err(ProtocolError::UnsupportedFrameVer(self.header.ver));
        }
        self.header.flags.validate(self.header.msg_type)?;
        if self.header.flags.prefix_kind()? != self.prefix.kind() {
            return Err(ProtocolError::UnexpectedPrefix);
        }
        let expected = self
            .prefix
            .encoded_len()
            .checked_add(self.body.len())
            .ok_or(ProtocolError::BadLen {
                len: self.header.len,
                prefix: self.prefix.encoded_len() as u8,
                cap: FRAME_MAX,
            })?;
        let expected_u32 = u32::try_from(expected).map_err(|_| ProtocolError::BadLen {
            len: self.header.len,
            prefix: self.prefix.encoded_len() as u8,
            cap: FRAME_MAX,
        })?;
        if expected_u32 != self.header.len {
            return Err(ProtocolError::BadLen {
                len: self.header.len,
                prefix: self.prefix.encoded_len() as u8,
                cap: expected_u32,
            });
        }
        if expected_u32 > FRAME_MAX {
            return Err(ProtocolError::BadLen {
                len: self.header.len,
                prefix: self.prefix.encoded_len() as u8,
                cap: FRAME_MAX,
            });
        }
        let min_body = self.header.msg_type.body_encoding().min_body_len();
        if self.body.len() < min_body as usize {
            return Err(ProtocolError::BodyTooShort {
                len: self.header.len,
                prefix: self.prefix.encoded_len() as u8,
                min_body,
            });
        }
        Ok(())
    }
}

/// Reusable frame encoder. One allocation, reused across frames.
#[derive(Debug, Default)]
pub struct FrameEncoder {
    buf: Vec<u8>,
}

impl FrameEncoder {
    /// Empty encoder.
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Encoder with a pre-sized buffer.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    /// Encode into the internal buffer and borrow the bytes.
    ///
    /// The borrow lasts until the next encoder call.
    pub fn encode(&mut self, frame: &FrameRef<'_>) -> Result<&[u8], ProtocolError> {
        frame.check()?;
        self.buf.clear();
        self.buf.extend_from_slice(&frame.header.encode());
        frame.prefix.encode_into(&mut self.buf);
        self.buf.extend_from_slice(frame.body);
        Ok(&self.buf)
    }

    /// Encode and copy into a fresh vector.
    pub fn encode_owned(&mut self, frame: &FrameRef<'_>) -> Result<Vec<u8>, ProtocolError> {
        Ok(self.encode(frame)?.to_vec())
    }

    /// Drop the buffered bytes, keeping the allocation.
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    /// Current buffer capacity.
    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }
}

/// Encode one frame without keeping an encoder.
pub fn encode_frame(frame: &FrameRef<'_>) -> Result<Vec<u8>, ProtocolError> {
    FrameEncoder::new().encode_owned(frame)
}

/// Consumed bytes below this threshold stay in place; moving them would cost
/// more than the wasted space.
const COMPACT_THRESHOLD: usize = 8 * 1024;

/// One decoded frame prefix and its total width.
struct Probe {
    header: FrameHeader,
    prefix_len: usize,
    total: usize,
}

/// Incremental frame decoder.
///
/// Invariants:
/// * a header is validated before any body bytes are awaited;
/// * `len` is checked against [`Limits`] before allocation or buffering;
/// * the internal buffer is bounded at twice the largest legal frame.
#[derive(Debug)]
pub struct FrameDecoder {
    limits: Limits,
    buf: Vec<u8>,
    start: usize,
}

impl FrameDecoder {
    /// Empty decoder.
    pub const fn new(limits: Limits) -> Self {
        Self {
            limits,
            buf: Vec::new(),
            start: 0,
        }
    }

    /// Decoder with a pre-sized buffer.
    pub fn with_capacity(limits: Limits, capacity: usize) -> Self {
        Self {
            limits,
            buf: Vec::with_capacity(capacity),
            start: 0,
        }
    }

    /// Current limits.
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Replace limits. Takes effect on the next frame.
    pub fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
    }

    /// Bytes pushed but not yet consumed.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }

    /// Whether no unconsumed bytes remain.
    pub fn is_empty(&self) -> bool {
        self.buffered() == 0
    }

    /// Drop every buffered byte.
    pub fn clear(&mut self) {
        self.buf.clear();
        self.start = 0;
    }

    /// Largest buffer this decoder will hold.
    fn max_buffered(&self) -> usize {
        let widest_prefix = if ROUTE_PREFIX_LEN > CTRL_PREFIX_LEN {
            ROUTE_PREFIX_LEN
        } else {
            CTRL_PREFIX_LEN
        };
        let frame = HEADER_LEN + widest_prefix + self.limits.effective_cap() as usize;
        frame.saturating_mul(2)
    }

    /// Append bytes.
    ///
    /// Rejects the push when the decoder would have to buffer more than two
    /// maximal frames. That is the only defence a sans-io decoder can offer
    /// against a peer that keeps sending without the caller consuming.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.compact();
        let cap = self.max_buffered();
        let projected =
            self.buffered()
                .checked_add(bytes.len())
                .ok_or(ProtocolError::BufferOverflow {
                    buffered: usize::MAX,
                    cap,
                })?;
        if projected > cap {
            return Err(ProtocolError::BufferOverflow {
                buffered: projected,
                cap,
            });
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    /// Move consumed bytes out of the way when it pays off.
    fn compact(&mut self) {
        if self.start == 0 {
            return;
        }
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
            return;
        }
        if self.start >= COMPACT_THRESHOLD || self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
    }

    /// Validate the next header and decide whether the frame is complete.
    ///
    /// A malformed length is reported immediately, without waiting for the
    /// body it claims: that is what makes a 4 GiB `len` harmless.
    fn probe(&self) -> Result<Option<Probe>, ProtocolError> {
        let available = self.buffered();
        if available < HEADER_LEN {
            return Ok(None);
        }
        let header = FrameHeader::decode(&self.buf[self.start..self.start + HEADER_LEN])?;
        let prefix_len = header.prefix_len()? as usize;
        header.validate_len(&self.limits)?;
        let total = HEADER_LEN + header.len as usize;
        if available < total {
            return Ok(None);
        }
        Ok(Some(Probe {
            header,
            prefix_len,
            total,
        }))
    }

    /// Borrow the next complete frame.
    ///
    /// Returns `Ok(None)` when more bytes are needed. The returned view
    /// borrows the internal buffer and dies before the next mutable call.
    pub fn next_frame(&mut self) -> Result<Option<Frame<'_>>, ProtocolError> {
        let probe = match self.probe()? {
            Some(probe) => probe,
            None => return Ok(None),
        };
        let base = self.start;
        let prefix_offset = base + HEADER_LEN;
        let body_offset = prefix_offset + probe.prefix_len;
        let body_end = base + probe.total;
        let prefix = Prefix::decode(
            probe.header.flags.prefix_kind()?,
            &self.buf[prefix_offset..body_offset],
        )?;
        self.start = body_end;
        Ok(Some(Frame {
            header: probe.header,
            prefix,
            body: &self.buf[body_offset..body_end],
        }))
    }

    /// Decode the next complete frame into an owned buffer.
    pub fn next_frame_owned(&mut self) -> Result<Option<FrameBuf>, ProtocolError> {
        Ok(self.next_frame()?.map(|frame| frame.to_buf()))
    }

    /// Signal end of stream.
    ///
    /// Returns `Ok(())` only when the decoder sits exactly on a frame
    /// boundary. Any residue is a truncation, not a shorter frame.
    pub fn finish(&mut self) -> Result<(), ProtocolError> {
        let available = self.buffered();
        if available == 0 {
            return Ok(());
        }
        if available < HEADER_LEN {
            return Err(ProtocolError::Truncated {
                need: HEADER_LEN,
                got: available,
            });
        }
        let header = FrameHeader::decode(&self.buf[self.start..self.start + HEADER_LEN])?;
        let total = HEADER_LEN + header.len as usize;
        Err(ProtocolError::Truncated {
            need: total,
            got: available,
        })
    }
}

/// Bytes pulled from the source per read call.
const READ_CHUNK: usize = 16 * 1024;

/// Synchronous frame reader over any [`Read`].
///
/// Only for golden vectors, unit tests and file-based fixtures. Production
/// transport must feed [`FrameDecoder`] from its own byte stream.
#[derive(Debug)]
pub struct FrameReader<R> {
    src: R,
    decoder: FrameDecoder,
    eof: bool,
}

impl<R: Read> FrameReader<R> {
    /// Wrap a reader.
    pub fn new(src: R, limits: Limits) -> Self {
        Self {
            src,
            decoder: FrameDecoder::new(limits),
            eof: false,
        }
    }

    /// Read the next frame, or `None` on a clean end of stream.
    pub fn next_frame(&mut self) -> Result<Option<FrameBuf>, ProtocolError> {
        loop {
            if let Some(frame) = self.decoder.next_frame_owned()? {
                return Ok(Some(frame));
            }
            if self.eof {
                self.decoder.finish()?;
                return Ok(None);
            }
            let mut chunk = [0u8; READ_CHUNK];
            let read = self.src.read(&mut chunk)?;
            if read == 0 {
                self.eof = true;
                continue;
            }
            self.decoder.push(&chunk[..read])?;
        }
    }

    /// Borrow the underlying decoder.
    pub const fn decoder(&self) -> &FrameDecoder {
        &self.decoder
    }

    /// Recover the source.
    pub fn into_inner(self) -> R {
        self.src
    }
}

/// Synchronous frame writer over any [`Write`].
#[derive(Debug)]
pub struct FrameWriter<W> {
    dst: W,
    encoder: FrameEncoder,
}

impl<W: Write> FrameWriter<W> {
    /// Wrap a writer.
    pub fn new(dst: W) -> Self {
        Self {
            dst,
            encoder: FrameEncoder::new(),
        }
    }

    /// Encode and write one frame.
    pub fn write(&mut self, frame: &FrameRef<'_>) -> Result<(), ProtocolError> {
        let bytes = self.encoder.encode_owned(frame)?;
        self.dst.write_all(&bytes)?;
        Ok(())
    }

    /// Flush the sink.
    pub fn flush(&mut self) -> std::io::Result<()> {
        self.dst.flush()
    }

    /// Recover the sink.
    pub fn into_inner(self) -> W {
        self.dst
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::protocol::frame::{
        BodyEncoding, CtrlPrefix, Flags, MsgType, PrefixKind, RoutePrefix, Seq, SessionId, StreamId,
    };
    use crate::protocol::{ENV_OVERHEAD, FRAME_MAX, INGRESS_FRAME};

    /// Golden `RELAY`: sealed, routed, 25-byte prefix, 30-byte envelope.
    const GOLDEN_RELAY: [u8; 76] = [
        0x53, 0x01, 0x12, 0x18, 0x00, 0x44, 0x33, 0x22, 0x11, 0x37, 0x00, 0x00, 0x00, 0x08, 0x07,
        0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07,
        0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x2a, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];

    fn golden_relay() -> FrameBuf {
        FrameBuf::new(
            FrameHeader {
                ver: 1,
                msg_type: MsgType::RELAY,
                flags: Flags::ENC.with(Flags::ROUTED),
                req_id: 0x1122_3344,
                len: 55,
                seq: Seq(0x0102_0304_0506_0708),
            },
            Prefix::Route(RoutePrefix::new(
                SessionId(0x0001_0203_0405_0607_0809_0a0b_0c0d_0e0f),
                StreamId(0x02),
                3,
                4,
            )),
            vec![
                0x00, 0x2a, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                0x1e, 0x1f,
            ],
        )
    }

    /// Build a legal frame of the requested type with a deterministic body.
    fn sample_frame(msg_type: MsgType) -> FrameBuf {
        let prefix = match msg_type.prefix_kind() {
            PrefixKind::None => Prefix::None,
            PrefixKind::Route => Prefix::Route(RoutePrefix::new(
                SessionId(0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00),
                StreamId::BLOCK,
                1,
                2,
            )),
            PrefixKind::Ctrl => Prefix::Ctrl(CtrlPrefix::new(Seq(9), 7)),
        };
        let mut flags = Flags::EMPTY;
        if msg_type.body_encoding().is_sealed() {
            flags = flags.with(Flags::ENC);
        }
        match msg_type.prefix_kind() {
            PrefixKind::None => {}
            PrefixKind::Route => flags = flags.with(Flags::ROUTED),
            PrefixKind::Ctrl => flags = flags.with(Flags::CTRL),
        }
        let body_len = match msg_type.body_encoding() {
            BodyEncoding::Plain => 5,
            BodyEncoding::Sealed => ENV_OVERHEAD as usize,
        };
        let body: Vec<u8> = (0..body_len).map(|index| index as u8).collect();
        let mut header = FrameHeader::new(msg_type, flags, 0x0102_0304, Seq(0));
        header.len = u32::try_from(prefix.encoded_len() + body.len()).expect("fits in u32");
        FrameBuf::new(header, prefix, body)
    }

    fn encode(frame: &FrameBuf) -> Vec<u8> {
        encode_frame(&FrameRef::new(&frame.header, &frame.prefix, &frame.body)).expect("encodes")
    }

    #[test]
    fn golden_relay_encodes_to_fixed_bytes() {
        assert_eq!(encode(&golden_relay()), GOLDEN_RELAY);
    }

    #[test]
    fn golden_relay_decodes_byte_for_byte() {
        let mut decoder = FrameDecoder::new(Limits::default());
        decoder.push(&GOLDEN_RELAY).expect("buffers");
        let frame = decoder
            .next_frame_owned()
            .expect("no error")
            .expect("one frame");
        assert_eq!(frame, golden_relay());
        assert!(decoder.next_frame_owned().expect("no error").is_none());
        assert!(decoder.is_empty());
    }

    #[test]
    fn every_type_roundtrips() {
        for msg_type in MsgType::ALL {
            let frame = sample_frame(msg_type);
            let bytes = encode(&frame);
            let mut decoder = FrameDecoder::new(Limits::default());
            decoder.push(&bytes).expect("buffers");
            let got = decoder
                .next_frame_owned()
                .expect("no error")
                .expect("one frame");
            assert_eq!(got.header, frame.header, "{msg_type:?} header");
            assert_eq!(got.prefix, frame.prefix, "{msg_type:?} prefix");
            assert_eq!(got.body, frame.body, "{msg_type:?} body");
            assert!(decoder.is_empty(), "{msg_type:?} leaves no residue");
        }
    }

    #[test]
    fn decoder_waits_for_every_byte() {
        let frame = golden_relay();
        let bytes = encode(&frame);
        let mut decoder = FrameDecoder::new(Limits::default());
        for index in 0..bytes.len() - 1 {
            decoder.push(&bytes[index..=index]).expect("buffers");
            assert!(
                decoder.next_frame_owned().expect("no error").is_none(),
                "prefix of {} bytes must not decode",
                index + 1
            );
        }
        decoder.push(&bytes[bytes.len() - 1..]).expect("buffers");
        let got = decoder
            .next_frame_owned()
            .expect("no error")
            .expect("one frame");
        assert_eq!(got, frame);
    }

    #[test]
    fn every_truncation_is_a_clean_wait_then_a_truncation_error() {
        let bytes = encode(&golden_relay());
        for cut in 0..bytes.len() {
            let mut decoder = FrameDecoder::new(Limits::default());
            decoder.push(&bytes[..cut]).expect("buffers");
            assert!(
                decoder.next_frame_owned().expect("no error").is_none(),
                "cut at {cut} must not decode"
            );
            if cut == 0 {
                assert!(decoder.finish().is_ok());
            } else {
                assert!(
                    matches!(decoder.finish(), Err(ProtocolError::Truncated { .. })),
                    "cut at {cut} must report truncation"
                );
            }
        }
    }

    #[test]
    fn sealed_body_length_boundaries() {
        // ORDERED has no prefix, so `len` is the body length.
        for (len, ok) in [(0u32, false), (29, false), (30, true), (31, true)] {
            let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq(0));
            header.len = len;
            let body = vec![0u8; len as usize];
            let frame = FrameRef::new(&header, &Prefix::None, &body);
            let result = encode_frame(&frame);
            assert_eq!(result.is_ok(), ok, "sealed len {len}");
            if let Err(error) = result {
                assert!(
                    matches!(error, ProtocolError::BodyTooShort { .. }),
                    "sealed len {len} must be BodyTooShort, got {error:?}"
                );
            }
        }
    }

    #[test]
    fn plain_body_length_boundaries() {
        for (len, ok) in [(0u32, false), (2, false), (3, true)] {
            let mut header = FrameHeader::new(MsgType::WELCOME, Flags::EMPTY, 0, Seq(0));
            header.len = len;
            let body = vec![0u8; len as usize];
            let frame = FrameRef::new(&header, &Prefix::None, &body);
            let result = encode_frame(&frame);
            assert_eq!(result.is_ok(), ok, "plain len {len}");
            if let Err(error) = result {
                assert!(
                    matches!(error, ProtocolError::BodyTooShort { .. }),
                    "plain len {len} must be BodyTooShort, got {error:?}"
                );
            }
        }
    }

    #[test]
    fn routed_length_boundaries_include_the_prefix() {
        // RELAY carries a 25-byte route prefix and a 30-byte minimum
        // envelope, so the shortest legal `len` is 55, not 30.
        let limits = Limits::default();
        for (len, ok) in [
            (0u32, false),
            (29, false),
            (30, false),
            (31, false),
            (54, false),
            (55, true),
        ] {
            let mut header =
                FrameHeader::new(MsgType::RELAY, Flags::ENC.with(Flags::ROUTED), 0, Seq(0));
            header.len = len;
            let mut decoder = FrameDecoder::new(limits);
            decoder.push(&header.encode()).expect("header fits");
            if ok {
                decoder
                    .push(&vec![0u8; len as usize])
                    .expect("complete body fits");
            }
            let result = decoder.next_frame_owned();
            assert_eq!(result.is_ok(), ok, "routed len {len}");
            if ok {
                let frame = result.expect("no error").expect("one frame");
                assert_eq!(frame.header.len, len);
                assert_eq!(frame.prefix.encoded_len(), ROUTE_PREFIX_LEN);
                assert_eq!(frame.body.len(), len as usize - ROUTE_PREFIX_LEN);
            }
        }
    }

    #[test]
    fn decoder_rejects_ctrl_prefix_with_nonzero_reserved() {
        let frame = sample_frame(MsgType::HELLO);
        let mut bytes = encode(&frame);
        let reserved_at = HEADER_LEN + CTRL_PREFIX_LEN - 2;
        bytes[reserved_at] = 1;
        let mut decoder = FrameDecoder::new(Limits::default());
        decoder.push(&bytes).expect("buffers");
        assert!(matches!(
            decoder.next_frame_owned(),
            Err(ProtocolError::NonZeroReserved(1))
        ));
    }

    #[test]
    fn decoder_rejects_reserved_flags_and_prefix_conflict() {
        let mut reserved = GOLDEN_RELAY;
        reserved[3] = 0x58; // ENC | ROUTED | bit6
        let mut decoder = FrameDecoder::new(Limits::default());
        decoder.push(&reserved).expect("buffers");
        assert!(matches!(
            decoder.next_frame_owned(),
            Err(ProtocolError::ReservedFlags(0x0058))
        ));

        let mut conflict = GOLDEN_RELAY;
        conflict[3] = 0x38; // ENC | ROUTED | CTRL
        let mut decoder = FrameDecoder::new(Limits::default());
        decoder.push(&conflict).expect("buffers");
        assert!(matches!(
            decoder.next_frame_owned(),
            Err(ProtocolError::FlagsConflict(0x0038))
        ));
    }

    #[test]
    fn decoder_ingress_boundary_counts_the_prefix() {
        let limits = Limits::default();
        for (len, ok) in [
            (INGRESS_FRAME - 1, true),
            (INGRESS_FRAME, true),
            (INGRESS_FRAME + 1, false),
        ] {
            let mut frame = sample_frame(MsgType::RELAY);
            frame.body = vec![0u8; len as usize - ROUTE_PREFIX_LEN];
            frame.header.len = len;
            let bytes = encode(&frame);
            assert_eq!(bytes.len(), HEADER_LEN + len as usize);

            let mut decoder = FrameDecoder::new(limits);
            decoder.push(&bytes).expect("fits within the decoder bound");
            let result = decoder.next_frame_owned();
            assert_eq!(result.is_ok(), ok, "routed ingress len {len}");
            match result {
                Ok(Some(got)) => assert_eq!(got.header.len, len),
                Ok(None) => panic!("a complete frame must decode"),
                Err(error) => assert!(matches!(error, ProtocolError::BadLen { .. })),
            }
        }
    }

    #[test]
    fn structural_header_flips_are_rejected() {
        // magic: every other value fails.
        for value in 0..=u8::MAX {
            if value == 0x53 {
                continue;
            }
            let mut bytes = GOLDEN_RELAY;
            bytes[0] = value;
            assert!(
                FrameHeader::decode(&bytes).is_err(),
                "magic {value:#04x} must fail"
            );
        }

        // version: v1 is the only accepted byte.
        for value in 0..=u8::MAX {
            if value == 1 {
                continue;
            }
            let mut bytes = GOLDEN_RELAY;
            bytes[1] = value;
            assert!(
                FrameHeader::decode(&bytes).is_err(),
                "version {value} must fail"
            );
        }

        // type: unknown values fail; the only known types that may survive
        // are those whose table row matches ENC | ROUTED.
        for value in 0..=u8::MAX {
            let mut bytes = GOLDEN_RELAY;
            bytes[2] = value;
            if let Ok(header) = FrameHeader::decode(&bytes) {
                assert!(
                    matches!(header.msg_type, MsgType::RELAY | MsgType::STREAM_DATA),
                    "type {value:#04x} survived with incompatible flags"
                );
            }
        }

        // flags: every illegal combination fails, every legal one passes.
        for value in 0..=u16::MAX {
            let mut bytes = GOLDEN_RELAY;
            bytes[3..5].copy_from_slice(&value.to_le_bytes());
            let illegal = value & 0x00c0 != 0
                || value & 0x0030 == 0x0030
                || value & 0x0008 == 0
                || value & 0x0010 == 0;
            assert_eq!(
                FrameHeader::decode(&bytes).is_err(),
                illegal,
                "flags {value:#06x}"
            );
        }
    }

    #[test]
    fn length_validation_rejects_every_out_of_range_value() {
        let mut header = golden_relay().header;

        for (len, ok) in [
            (0u32, false),
            (1, false),
            (54, false),
            (55, true),
            (INGRESS_FRAME, true),
            (INGRESS_FRAME + 1, false),
        ] {
            header.len = len;
            assert_eq!(
                header.validate_len(&Limits::default()).is_ok(),
                ok,
                "ingress len {len}"
            );
        }

        for (len, ok) in [(FRAME_MAX, true), (FRAME_MAX + 1, false)] {
            header.len = len;
            assert_eq!(
                header.validate_len(&Limits::protocol()).is_ok(),
                ok,
                "protocol len {len}"
            );
        }
    }

    #[test]
    fn every_single_byte_flip_is_safe_and_self_consistent() {
        // V2: no flip may panic, and a flip that still decodes must describe
        // exactly the bytes it consumed. Structural positions that make the
        // frame illegal are covered by `structural_header_flips_are_rejected`;
        // `seq`, `req_id`, prefix payload and body bytes are intentionally
        // unauthenticated at this layer (49 A11 puts `seq` outside the AAD).
        for index in 0..GOLDEN_RELAY.len() {
            for value in 0..=u8::MAX {
                if value == GOLDEN_RELAY[index] {
                    continue;
                }
                let mut bytes = GOLDEN_RELAY;
                bytes[index] = value;
                let mut decoder = FrameDecoder::new(Limits::default());
                decoder.push(&bytes).expect("the fixed vector always fits");
                match decoder.next_frame_owned() {
                    Ok(Some(frame)) => {
                        let consumed = HEADER_LEN + frame.header.len as usize;
                        assert_eq!(
                            encode(&frame),
                            bytes[..consumed],
                            "flip at {index} to {value:#04x} decoded inconsistently"
                        );
                    }
                    Ok(None) => {
                        let header = FrameHeader::decode(&bytes[..HEADER_LEN])
                            .expect("None is only possible after a valid header");
                        assert!(
                            HEADER_LEN + header.len as usize > bytes.len(),
                            "flip at {index} to {value:#04x} waited for a complete frame"
                        );
                    }
                    Err(error) => {
                        if (9..13).contains(&index) {
                            let len =
                                u32::from_le_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]);
                            assert!(
                                !(55..=INGRESS_FRAME).contains(&len),
                                "flip at {index} to {value:#04x} rejected legal len {len}: {error:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn ingress_boundary_is_inclusive() {
        let limits = Limits::default();
        assert_eq!(limits.ingress_frame, INGRESS_FRAME);
        for (len, ok) in [
            (INGRESS_FRAME - 1, true),
            (INGRESS_FRAME, true),
            (INGRESS_FRAME + 1, false),
        ] {
            let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq(0));
            header.len = len;
            let body = vec![0u8; len as usize];
            let frame = FrameRef::new(&header, &Prefix::None, &body);
            let mut decoder = FrameDecoder::new(limits);
            let encoded = encode_frame(&frame).expect("encoder does not apply ingress limits");
            decoder.push(&encoded).expect("buffers within cap");
            let result = decoder.next_frame_owned();
            assert_eq!(result.is_ok(), ok, "ingress len {len}");
            if let Err(error) = result {
                assert!(
                    matches!(error, ProtocolError::BadLen { .. }),
                    "ingress len {len} must be BadLen, got {error:?}"
                );
            }
        }
    }

    #[test]
    fn decoder_rejects_flood_beyond_its_bound() {
        let limits = Limits::default();
        let mut decoder = FrameDecoder::new(limits);
        let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq(0));
        header.len = INGRESS_FRAME;
        decoder.push(&header.encode()).expect("header fits");
        // Two maximal frames plus slack: the decoder holds at most two.
        let flood = vec![0u8; INGRESS_FRAME as usize * 3];
        assert!(matches!(
            decoder.push(&flood),
            Err(ProtocolError::BufferOverflow { .. })
        ));
    }

    #[test]
    fn encoder_rejects_len_mismatch() {
        let frame = golden_relay();
        let mut header = frame.header;
        header.len += 1;
        let error = encode_frame(&FrameRef::new(&header, &frame.prefix, &frame.body))
            .expect_err("len mismatch must fail");
        assert!(matches!(error, ProtocolError::BadLen { .. }));
    }

    #[test]
    fn encoder_rejects_prefix_kind_mismatch() {
        let frame = sample_frame(MsgType::WELCOME);
        let route = Prefix::Route(RoutePrefix::new(SessionId::ZERO, StreamId::BLOCK, 0, 0));
        let error = encode_frame(&FrameRef::new(&frame.header, &route, &frame.body))
            .expect_err("prefix mismatch must fail");
        assert!(matches!(error, ProtocolError::UnexpectedPrefix));
    }

    #[test]
    fn encoder_rejects_short_sealed_body() {
        let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq(0));
        header.len = 29;
        let body = vec![0u8; 29];
        let error = encode_frame(&FrameRef::new(&header, &Prefix::None, &body))
            .expect_err("short body must fail");
        assert!(matches!(
            error,
            ProtocolError::BodyTooShort {
                len: 29,
                prefix: 0,
                min_body: 30
            }
        ));
    }

    #[test]
    fn decoder_handles_several_frames_in_one_push() {
        let frames = [
            sample_frame(MsgType::HELLO),
            sample_frame(MsgType::ORDERED),
            sample_frame(MsgType::RELAY),
        ];
        let mut stream = Vec::new();
        for frame in &frames {
            stream.extend_from_slice(&encode(frame));
        }
        let mut decoder = FrameDecoder::new(Limits::default());
        decoder.push(&stream).expect("buffers");
        for expected in &frames {
            let got = decoder
                .next_frame_owned()
                .expect("no error")
                .expect("one frame");
            assert_eq!(&got, expected);
        }
        assert!(decoder.next_frame_owned().expect("no error").is_none());
    }

    #[test]
    fn decoder_reclaims_consumed_prefix() {
        let frame = sample_frame(MsgType::ORDERED);
        let bytes = encode(&frame);
        let mut decoder = FrameDecoder::new(Limits::default());
        for _ in 0..64 {
            decoder.push(&bytes).expect("buffers");
            let got = decoder
                .next_frame_owned()
                .expect("no error")
                .expect("one frame");
            assert_eq!(got, frame);
        }
        assert!(decoder.is_empty());
        assert!(decoder.buf.len() <= bytes.len() * 2);
    }

    #[test]
    fn frame_reader_reports_clean_eof_and_truncation() {
        let bytes = encode(&golden_relay());

        let mut reader = FrameReader::new(&bytes[..], Limits::default());
        assert_eq!(reader.next_frame().expect("no error"), Some(golden_relay()));
        assert_eq!(reader.next_frame().expect("no error"), None);

        let mut reader = FrameReader::new(&bytes[..bytes.len() - 1], Limits::default());
        assert!(matches!(
            reader.next_frame(),
            Err(ProtocolError::Truncated { .. })
        ));
    }

    #[test]
    fn frame_writer_matches_encoder() {
        let frame = golden_relay();
        let mut sink = Vec::new();
        {
            let mut writer = FrameWriter::new(&mut sink);
            writer
                .write(&FrameRef::new(&frame.header, &frame.prefix, &frame.body))
                .expect("writes");
            writer.flush().expect("flushes");
        }
        assert_eq!(sink, GOLDEN_RELAY);
    }

    /// A deliberately independent encoder for V13.
    ///
    /// It walks the offset table in 44 §2.1 by hand instead of calling
    /// [`FrameHeader::encode`] or [`Prefix::encode_into`]. The Python half of
    /// V13 reproduces the same offsets; this test catches an implementation
    /// that is self-consistent but disagrees with the document.
    fn reference_encode(frame: &FrameBuf) -> Vec<u8> {
        let prefix_len = frame.prefix.encoded_len();
        let mut out = vec![0u8; HEADER_LEN + prefix_len + frame.body.len()];
        out[0] = 0x53;
        out[1] = frame.header.ver;
        out[2] = frame.header.msg_type.get();
        out[3] = frame.header.flags.bits() as u8;
        out[4] = (frame.header.flags.bits() >> 8) as u8;
        out[5..9].copy_from_slice(&frame.header.req_id.to_le_bytes());
        out[9..13].copy_from_slice(&frame.header.len.to_le_bytes());
        out[13..21].copy_from_slice(&frame.header.seq.get().to_le_bytes());
        match &frame.prefix {
            Prefix::None => {}
            Prefix::Route(route) => {
                out[21..37].copy_from_slice(&route.session_id.get().to_le_bytes());
                out[37] = route.stream.get();
                out[38..42].copy_from_slice(&route.chunk_index.to_le_bytes());
                out[42..46].copy_from_slice(&route.total_chunks.to_le_bytes());
            }
            Prefix::Ctrl(ctrl) => {
                out[21..29].copy_from_slice(&ctrl.applied_seq.get().to_le_bytes());
                out[29..37].copy_from_slice(&ctrl.epoch_seen.to_le_bytes());
                out[37..39].copy_from_slice(&ctrl.reserved.to_le_bytes());
            }
        }
        let body_at = HEADER_LEN + prefix_len;
        out[body_at..].copy_from_slice(&frame.body);
        out
    }

    #[test]
    fn independent_reference_encoder_matches_wire_bytes() {
        let relay = golden_relay();
        assert_eq!(reference_encode(&relay), GOLDEN_RELAY);

        // Cover all three prefix families and both body encodings.
        for msg_type in [
            MsgType::WELCOME,
            MsgType::HELLO,
            MsgType::RELAY,
            MsgType::STREAM_DATA,
        ] {
            let frame = sample_frame(msg_type);
            assert_eq!(
                reference_encode(&frame),
                encode(&frame),
                "{msg_type:?} reference bytes"
            );
        }
    }

    #[test]
    fn header_shortfall_is_reported_before_body_wait() {
        let mut decoder = FrameDecoder::new(Limits::default());
        decoder.push(&[0x53, 0x01]).expect("buffers");
        assert!(decoder.next_frame_owned().expect("no error").is_none());
        assert!(matches!(
            decoder.finish(),
            Err(ProtocolError::Truncated { need: 21, got: 2 })
        ));
    }

    #[test]
    fn oversized_len_is_rejected_before_the_body_arrives() {
        let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq(0));
        header.len = INGRESS_FRAME + 1;
        let mut decoder = FrameDecoder::new(Limits::default());
        decoder.push(&header.encode()).expect("header fits");
        assert!(matches!(
            decoder.next_frame_owned(),
            Err(ProtocolError::BadLen { .. })
        ));
    }

    use proptest::prelude::*;

    fn arb_frame() -> impl Strategy<Value = FrameBuf> {
        (
            prop::sample::select(MsgType::ALL.to_vec()),
            any::<u32>(),
            any::<u64>(),
            prop::collection::vec(any::<u8>(), 0..96),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
        )
            .prop_map(|(msg_type, req_id, seq, tail, urgent, fin, compressed)| {
                let prefix = match msg_type.prefix_kind() {
                    PrefixKind::None => Prefix::None,
                    PrefixKind::Route => Prefix::Route(RoutePrefix::new(
                        SessionId((u128::from(seq) << 64) | u128::from(req_id)),
                        StreamId(tail.first().copied().unwrap_or(0)),
                        tail.len() as u32,
                        (tail.len() as u32).saturating_add(1),
                    )),
                    PrefixKind::Ctrl => Prefix::Ctrl(CtrlPrefix::new(Seq(seq), u64::from(req_id))),
                };
                let mut flags = Flags::EMPTY;
                if msg_type.body_encoding().is_sealed() {
                    flags = flags.with(Flags::ENC);
                }
                match msg_type.prefix_kind() {
                    PrefixKind::None => {}
                    PrefixKind::Route => flags = flags.with(Flags::ROUTED),
                    PrefixKind::Ctrl => flags = flags.with(Flags::CTRL),
                }
                if urgent {
                    flags = flags.with(Flags::URGENT);
                }
                if fin {
                    flags = flags.with(Flags::FIN);
                }
                if compressed {
                    flags = flags.with(Flags::COMPRESSED);
                }
                let mut body = vec![0u8; msg_type.body_encoding().min_body_len() as usize];
                body.extend_from_slice(&tail);
                let mut header = FrameHeader::new(msg_type, flags, req_id, Seq(seq));
                header.len = u32::try_from(prefix.encoded_len() + body.len()).expect("fits in u32");
                FrameBuf::new(header, prefix, body)
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn arbitrary_frames_roundtrip(frame in arb_frame()) {
            let bytes = encode(&frame);
            let mut decoder = FrameDecoder::new(Limits::default());
            decoder.push(&bytes).expect("buffers");
            let got = decoder
                .next_frame_owned()
                .expect("no error")
                .expect("one frame");
            prop_assert_eq!(&got.header, &frame.header);
            prop_assert_eq!(&got.prefix, &frame.prefix);
            prop_assert_eq!(&got.body, &frame.body);
            prop_assert!(decoder.next_frame_owned().expect("no error").is_none());
        }

        #[test]
        fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
            let mut decoder = FrameDecoder::new(Limits::default());
            if decoder.push(&bytes).is_err() {
                return Ok(());
            }
            while let Ok(Some(_)) = decoder.next_frame_owned() {}
        }

        #[test]
        fn frame_reader_never_panics_on_arbitrary_bytes(
            bytes in prop::collection::vec(any::<u8>(), 0..4096),
        ) {
            // V10 names `FrameReader` as an entry point. Each successful
            // frame consumes at least HEADER_LEN bytes, so this loop is
            // bounded without a counter.
            let mut reader = FrameReader::new(&bytes[..], Limits::default());
            while let Ok(Some(_)) = reader.next_frame() {}
        }

        #[test]
        fn single_byte_corruption_never_panics(
            index in 0usize..GOLDEN_RELAY.len(),
            value in any::<u8>(),
        ) {
            let mut bytes = GOLDEN_RELAY;
            bytes[index] = value;
            let mut decoder = FrameDecoder::new(Limits::default());
            if decoder.push(&bytes).is_err() {
                return Ok(());
            }
            while let Ok(Some(_)) = decoder.next_frame_owned() {}
        }
    }
}
