//! Streaming SMM1 frames.
//!
//! The meta stream is bounded (16 MiB by default) and held in memory; the
//! payload is not. [`SmmReader`] exposes it as a `Read`-like stream and hashes
//! it as it goes, so a 64 GiB body costs one fixed buffer. [`SmmWriter`] writes
//! the header and meta first and then accepts payload chunks, refusing to
//! exceed the declared `data_len`.
//!
//! The hashes returned in [`PayloadDigest`] are exactly the values the request
//! MAC binds, so a caller verifies the MAC after the body has been streamed.

use std::io::{Read, Write};

use super::error::ProtoError;
use super::header::{HEADER_LEN, Header};
use super::kind::Kind;
use super::limits::Limits;

/// Hashes of a complete frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayloadDigest {
    /// BLAKE3 of the meta bytes.
    pub meta_hash: [u8; 32],
    /// BLAKE3 of the payload bytes.
    pub payload_hash: [u8; 32],
    /// Payload length.
    pub data_len: u64,
}

/// Reads one SMM1 frame from a byte stream.
#[derive(Debug)]
pub struct SmmReader<R: Read> {
    inner: R,
    header: Header,
    meta: Vec<u8>,
    meta_hash: [u8; 32],
    remaining: u64,
    payload: blake3::Hasher,
}

impl<R: Read> SmmReader<R> {
    /// Read the header and meta, leaving the payload unread.
    ///
    /// # Errors
    ///
    /// Any header, limit, truncation or I/O error.
    pub fn open(mut inner: R, limits: &Limits) -> Result<Self, ProtoError> {
        let mut header_bytes = [0u8; HEADER_LEN];
        read_exact(&mut inner, &mut header_bytes)?;
        let header = Header::decode_with_limits(&header_bytes, limits)?;
        let mut meta = vec![0u8; header.meta_len as usize];
        read_exact(&mut inner, &mut meta)?;
        let meta_hash = *blake3::hash(&meta).as_bytes();
        Ok(Self {
            inner,
            header,
            meta,
            meta_hash,
            remaining: header.data_len,
            payload: blake3::Hasher::new(),
        })
    }

    /// The decoded header.
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// The meta bytes.
    pub fn meta(&self) -> &[u8] {
        &self.meta
    }

    /// BLAKE3 of the meta bytes.
    pub const fn meta_hash(&self) -> [u8; 32] {
        self.meta_hash
    }

    /// Payload bytes not yet read.
    pub const fn remaining(&self) -> u64 {
        self.remaining
    }

    /// Read some payload bytes. Returns `Ok(0)` at the end.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Truncated`] if the stream ends before `data_len`.
    pub fn read_payload(&mut self, buf: &mut [u8]) -> Result<usize, ProtoError> {
        if self.remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = usize::try_from(self.remaining.min(buf.len() as u64)).unwrap_or(buf.len());
        let got = self.inner.read(&mut buf[..want])?;
        if got == 0 {
            return Err(ProtoError::Truncated {
                need: self.remaining as usize,
                got: 0,
            });
        }
        self.payload.update(&buf[..got]);
        self.remaining -= got as u64;
        Ok(got)
    }

    /// Fill `buf` completely from the payload.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Truncated`] when fewer bytes remain.
    pub fn read_exact_payload(&mut self, buf: &mut [u8]) -> Result<(), ProtoError> {
        if buf.len() as u64 > self.remaining {
            return Err(ProtoError::Truncated {
                need: buf.len(),
                got: self.remaining as usize,
            });
        }
        let mut filled = 0;
        while filled < buf.len() {
            let got = self.read_payload(&mut buf[filled..])?;
            if got == 0 {
                return Err(ProtoError::Truncated {
                    need: buf.len(),
                    got: filled,
                });
            }
            filled += got;
        }
        Ok(())
    }

    /// Read the rest of the payload into `sink`.
    ///
    /// # Errors
    ///
    /// Any read or write error.
    pub fn copy_payload(&mut self, sink: &mut impl Write) -> Result<u64, ProtoError> {
        let mut copied = 0u64;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let got = self.read_payload(&mut buf)?;
            if got == 0 {
                return Ok(copied);
            }
            sink.write_all(&buf[..got])?;
            copied += got as u64;
        }
    }

    /// Finish the frame, requiring that the payload was fully consumed.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Truncated`] when payload bytes remain.
    pub fn finish(self) -> Result<PayloadDigest, ProtoError> {
        if self.remaining != 0 {
            return Err(ProtoError::Truncated {
                need: self.remaining as usize,
                got: 0,
            });
        }
        Ok(PayloadDigest {
            meta_hash: self.meta_hash,
            payload_hash: *self.payload.finalize().as_bytes(),
            data_len: self.header.data_len,
        })
    }

    /// Consume the reader and return the inner stream plus the digest.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Truncated`] when payload bytes remain.
    pub fn into_inner(self) -> Result<(R, PayloadDigest), ProtoError> {
        if self.remaining != 0 {
            return Err(ProtoError::Truncated {
                need: self.remaining as usize,
                got: 0,
            });
        }
        let digest = PayloadDigest {
            meta_hash: self.meta_hash,
            payload_hash: *self.payload.finalize().as_bytes(),
            data_len: self.header.data_len,
        };
        Ok((self.inner, digest))
    }
}

/// Writes one SMM1 frame.
#[derive(Debug)]
pub struct SmmWriter<W: Write> {
    inner: W,
    header: Header,
    meta_hash: [u8; 32],
    written: u64,
    payload: blake3::Hasher,
}

impl<W: Write> SmmWriter<W> {
    /// Write the header and meta. The payload must follow.
    ///
    /// # Errors
    ///
    /// Any field, limit or I/O error.
    pub fn begin(
        mut inner: W,
        kind: Kind,
        meta: &[u8],
        data_len: u64,
        limits: &Limits,
    ) -> Result<Self, ProtoError> {
        let meta_len = u32::try_from(meta.len()).map_err(|_| ProtoError::MetaTooLarge {
            len: meta.len() as u64,
            cap: u64::from(limits.max_meta_len),
        })?;
        let header = Header::new(kind, meta_len, data_len, limits)?;
        inner.write_all(&header.encode())?;
        inner.write_all(meta)?;
        let meta_hash = *blake3::hash(meta).as_bytes();
        Ok(Self {
            inner,
            header,
            meta_hash,
            written: 0,
            payload: blake3::Hasher::new(),
        })
    }

    /// The header already written.
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// Payload bytes written so far.
    pub const fn written(&self) -> u64 {
        self.written
    }

    /// Append payload bytes.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Inconsistent`] when the declared `data_len` would be
    /// exceeded, or an I/O error.
    pub fn write_payload(&mut self, bytes: &[u8]) -> Result<(), ProtoError> {
        if bytes.len() as u64 > self.header.data_len - self.written {
            return Err(ProtoError::Inconsistent("payload exceeds data_len"));
        }
        self.inner.write_all(bytes)?;
        self.payload.update(bytes);
        self.written += bytes.len() as u64;
        Ok(())
    }

    /// Finish the frame and return the inner stream plus the digest.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Inconsistent`] when the payload is short, or an I/O
    /// error.
    pub fn finish(mut self) -> Result<(W, PayloadDigest), ProtoError> {
        if self.written != self.header.data_len {
            return Err(ProtoError::Inconsistent("payload shorter than data_len"));
        }
        self.inner.flush()?;
        let digest = PayloadDigest {
            meta_hash: self.meta_hash,
            payload_hash: *self.payload.finalize().as_bytes(),
            data_len: self.header.data_len,
        };
        Ok((self.inner, digest))
    }
}

fn read_exact(reader: &mut impl Read, buf: &mut [u8]) -> Result<(), ProtoError> {
    let mut filled = 0;
    while filled < buf.len() {
        let got = reader.read(&mut buf[filled..])?;
        if got == 0 {
            return Err(ProtoError::Truncated {
                need: buf.len(),
                got: filled,
            });
        }
        filled += got;
    }
    Ok(())
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::io::Cursor;

    fn frame(meta: &[u8], payload: &[u8]) -> Vec<u8> {
        let limits = Limits::new();
        let mut writer = SmmWriter::begin(
            Vec::new(),
            Kind::FileData,
            meta,
            payload.len() as u64,
            &limits,
        )
        .unwrap();
        writer.write_payload(payload).unwrap();
        writer.finish().unwrap().0
    }

    #[test]
    fn reader_and_writer_round_trip() {
        let limits = Limits::new();
        let meta = b"meta-bytes";
        let payload = b"payload-bytes";
        let bytes = frame(meta, payload);

        let mut reader = SmmReader::open(Cursor::new(bytes), &limits).unwrap();
        assert_eq!(reader.header().kind, Kind::FileData);
        assert_eq!(reader.meta(), meta);
        assert_eq!(reader.remaining(), payload.len() as u64);
        let mut got = Vec::new();
        reader.copy_payload(&mut got).unwrap();
        assert_eq!(got, payload);
        let digest = reader.finish().unwrap();
        assert_eq!(digest.meta_hash, *blake3::hash(meta).as_bytes());
        assert_eq!(digest.payload_hash, *blake3::hash(payload).as_bytes());
        assert_eq!(digest.data_len, payload.len() as u64);
    }

    #[test]
    fn payload_is_read_in_small_pieces() {
        let limits = Limits::new();
        let meta = b"m";
        let payload = vec![0x5Au8; 10_000];
        let bytes = frame(meta, &payload);
        let mut reader = SmmReader::open(Cursor::new(bytes), &limits).unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 7];
        loop {
            let n = reader.read_payload(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, payload);
        reader.finish().unwrap();
    }

    #[test]
    fn short_payload_is_truncated() {
        let limits = Limits::new();
        let mut bytes = frame(b"m", b"0123456789");
        bytes.truncate(bytes.len() - 1);
        let mut reader = SmmReader::open(Cursor::new(bytes), &limits).unwrap();
        let mut got = Vec::new();
        assert!(reader.copy_payload(&mut got).is_err());
    }

    #[test]
    fn short_header_and_meta_are_truncated() {
        let limits = Limits::new();
        for cut in [0usize, 1, 23] {
            let bytes = frame(b"meta", b"");
            assert!(SmmReader::open(Cursor::new(&bytes[..cut]), &limits).is_err());
        }
        let mut bytes = frame(b"meta", b"");
        bytes.truncate(24 + 2);
        assert!(matches!(
            SmmReader::open(Cursor::new(bytes), &limits),
            Err(ProtoError::Truncated { .. })
        ));
    }

    #[test]
    fn writer_refuses_to_overrun_data_len() {
        let limits = Limits::new();
        let mut writer = SmmWriter::begin(Vec::new(), Kind::FileData, b"", 3, &limits).unwrap();
        writer.write_payload(b"abc").unwrap();
        assert!(matches!(
            writer.write_payload(b"d"),
            Err(ProtoError::Inconsistent(_))
        ));
        writer.finish().unwrap();
    }

    #[test]
    fn writer_refuses_a_short_finish() {
        let limits = Limits::new();
        let mut writer = SmmWriter::begin(Vec::new(), Kind::FileData, b"", 3, &limits).unwrap();
        writer.write_payload(b"ab").unwrap();
        assert!(matches!(writer.finish(), Err(ProtoError::Inconsistent(_))));
    }

    #[test]
    fn reader_refuses_finish_with_unread_payload() {
        let limits = Limits::new();
        let bytes = frame(b"m", b"payload");
        let reader = SmmReader::open(Cursor::new(bytes), &limits).unwrap();
        assert!(matches!(reader.finish(), Err(ProtoError::Truncated { .. })));
    }

    #[test]
    fn oversized_meta_is_refused_before_reading_the_body() {
        let limits = Limits {
            max_meta_len: 4,
            ..Limits::new()
        };
        let mut bytes = frame(b"12345", b"");
        // Rebuild the header for the small cap so the length check is the
        // only failure.
        bytes[8..12].copy_from_slice(&5u32.to_le_bytes());
        assert!(matches!(
            SmmReader::open(Cursor::new(bytes), &limits),
            Err(ProtoError::MetaTooLarge { .. })
        ));
    }

    #[test]
    fn read_exact_payload_reports_short_remainder() {
        let limits = Limits::new();
        let bytes = frame(b"m", b"1234");
        let mut reader = SmmReader::open(Cursor::new(bytes), &limits).unwrap();
        let mut buf = [0u8; 8];
        assert!(matches!(
            reader.read_exact_payload(&mut buf),
            Err(ProtoError::Truncated { .. })
        ));
    }
}
