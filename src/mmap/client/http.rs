//! Minimal synchronous HTTP/1.1 transport for SMM1.
//!
//! One request owns one TCP connection and always sends
//! `Connection: close`. That removes keep-alive and pipelining from the
//! client's correctness surface while staying inside HTTP/1.1. Request
//! payloads are streamed from the prepared commit plan; responses are read
//! into one buffer because the shadow trait returns owned bodies anyway.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use crate::mmap::proto::{
    ErrorBody, ErrorCode, HEADER_LEN, HEADER_MAC, HEADER_SEQ, HEADER_SESSION, Header, Kind, Limits,
    MacParts, Message, SessionKeys,
};

use super::wire::CommitPlan;

/// Authentication parts for one request.
#[derive(Clone, Debug)]
pub(super) struct RequestAuth {
    pub keys: Arc<SessionKeys>,
    pub seq: u64,
    pub generation: u64,
}

/// A complete HTTP response.
#[derive(Debug)]
pub(super) struct WireResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl WireResponse {
    /// Decode the SMM1 body as `M`.
    pub fn decode<M: Message>(&self) -> Result<M, WireFailure> {
        if self.status != 200 {
            return Err(self.failure());
        }
        let (header, meta) = self.frame()?;
        if header.kind == Kind::Error {
            let error = decode_error(&self.body, self.status)?;
            return Err(WireFailure::Status {
                status: self.status,
                body: Box::new(error),
            });
        }
        if header.kind != M::KIND {
            return Err(WireFailure::Protocol(format!(
                "expected {}, got {}",
                M::KIND.name(),
                header.kind.name()
            )));
        }
        crate::mmap::proto::decode_frame::<M>(&header, &meta).map_err(WireFailure::from_proto)
    }

    /// Decode a terminal error body, or synthesize one from the status.
    pub fn into_failure(self) -> WireFailure {
        self.failure()
    }

    fn failure(&self) -> WireFailure {
        if self.body.is_empty() {
            return WireFailure::Status {
                status: self.status,
                body: Box::new(ErrorBody::new(fallback_code(self.status))),
            };
        }
        match decode_error(&self.body, self.status) {
            Ok(body) => WireFailure::Status {
                status: self.status,
                body: Box::new(body),
            },
            Err(_) => WireFailure::Status {
                status: self.status,
                body: Box::new(ErrorBody::new(fallback_code(self.status))),
            },
        }
    }

    fn frame(&self) -> Result<(Header, Vec<u8>), WireFailure> {
        if self.body.len() < HEADER_LEN {
            return Err(WireFailure::Protocol(format!(
                "response is {} bytes, shorter than the SMM1 header",
                self.body.len()
            )));
        }
        let header = Header::decode_with_limits(&self.body[..HEADER_LEN], &Limits::new())
            .map_err(WireFailure::from_proto)?;
        let meta_end = HEADER_LEN
            .checked_add(header.meta_len as usize)
            .ok_or_else(|| WireFailure::Protocol("response meta overflows".to_owned()))?;
        let payload_end = meta_end
            .checked_add(header.data_len as usize)
            .ok_or_else(|| WireFailure::Protocol("response payload overflows".to_owned()))?;
        if payload_end != self.body.len() {
            return Err(WireFailure::Protocol(format!(
                "response frame declares {payload_end} bytes, carried {}",
                self.body.len()
            )));
        }
        Ok((header, self.body[HEADER_LEN..meta_end].to_vec()))
    }

    /// The response payload bytes.
    pub fn payload(&self) -> Result<&[u8], WireFailure> {
        let (header, _) = self.frame()?;
        let payload_start = HEADER_LEN + header.meta_len as usize;
        Ok(&self.body[payload_start..])
    }
}

/// A failed exchange.
#[derive(Debug)]
pub(super) enum WireFailure {
    /// The server answered with an SMM1 `ERROR` frame.
    Status { status: u16, body: Box<ErrorBody> },
    /// The connection failed before a complete response arrived.
    Transport(String),
    /// The peer answered with bytes that violate the contract.
    Protocol(String),
}

impl WireFailure {
    pub fn from_proto(error: crate::mmap::proto::ProtoError) -> Self {
        Self::Protocol(error.to_string())
    }

    /// The SMM1 error code, when the server supplied one.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Status { body, .. } => Some(body.code),
            Self::Transport(_) | Self::Protocol(_) => None,
        }
    }

    pub fn is_status(&self, code: ErrorCode) -> bool {
        self.code() == Some(code)
    }
}

fn decode_error(body: &[u8], status: u16) -> Result<ErrorBody, WireFailure> {
    if body.len() < HEADER_LEN {
        return Err(WireFailure::Status {
            status,
            body: Box::new(ErrorBody::new(fallback_code(status))),
        });
    }
    let header = Header::decode_with_limits(&body[..HEADER_LEN], &Limits::new())
        .map_err(WireFailure::from_proto)?;
    if header.kind != Kind::Error || header.data_len != 0 {
        return Err(WireFailure::Protocol(format!(
            "HTTP {status} carried {} instead of ERROR",
            header.kind.name()
        )));
    }
    let meta_end = HEADER_LEN + header.meta_len as usize;
    if meta_end != body.len() {
        return Err(WireFailure::Protocol(
            "error frame length does not match its header".to_owned(),
        ));
    }
    crate::mmap::proto::decode_frame::<ErrorBody>(&header, &body[HEADER_LEN..meta_end])
        .map_err(WireFailure::from_proto)
}

fn fallback_code(status: u16) -> ErrorCode {
    match status {
        400 => ErrorCode::BadRequest,
        401 => ErrorCode::AuthFailed,
        404 => ErrorCode::DirNotFound,
        409 => ErrorCode::BaseChanged,
        413 => ErrorCode::TooLarge,
        423 => ErrorCode::LockLost,
        503 => ErrorCode::Busy,
        507 => ErrorCode::NoSpace,
        _ => ErrorCode::Internal,
    }
}

/// Open one connection, send one frame, read one response.
#[allow(clippy::too_many_arguments)]
pub(super) fn exchange(
    addrs: &[SocketAddr],
    host_header: &str,
    connect_timeout: Duration,
    request_timeout: Duration,
    method: &str,
    path: &str,
    frame: Option<(Kind, &[u8])>,
    payload: Option<&CommitPlan<'_>>,
    auth: Option<&RequestAuth>,
    limits: &Limits,
) -> Result<WireResponse, WireFailure> {
    let stream = connect(addrs, connect_timeout)?;
    stream
        .set_read_timeout(Some(request_timeout))
        .map_err(|error| WireFailure::Transport(format!("read timeout: {error}")))?;
    stream
        .set_write_timeout(Some(request_timeout))
        .map_err(|error| WireFailure::Transport(format!("write timeout: {error}")))?;

    let data_len = payload.map_or(0, |plan| plan.data_len);
    let payload_hash =
        payload.map_or_else(|| *blake3::hash(b"").as_bytes(), |plan| plan.payload_hash);
    let meta = frame.map_or(&[][..], |(_, meta)| meta);
    let meta_hash = *blake3::hash(meta).as_bytes();
    let body_len = if frame.is_some() {
        HEADER_LEN as u64 + meta.len() as u64 + data_len
    } else {
        0
    };

    let mut request = Vec::with_capacity(512);
    request.extend_from_slice(method.as_bytes());
    request.push(b' ');
    request.extend_from_slice(path.as_bytes());
    request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    request.extend_from_slice(host_header.as_bytes());
    request.extend_from_slice(b"\r\nConnection: close\r\n");
    if frame.is_some() {
        request.extend_from_slice(b"Content-Type: application/x-syncmount-mm\r\n");
    }
    request.extend_from_slice(b"Content-Length: ");
    request.extend_from_slice(body_len.to_string().as_bytes());
    request.extend_from_slice(b"\r\n");
    if let Some(auth) = auth {
        let keys = &auth.keys;
        let parts = MacParts {
            method,
            path,
            seq: auth.seq,
            meta_hash,
            payload_hash,
        };
        let mac = keys.mac(&parts).map_err(|error| {
            WireFailure::Protocol(format!("cannot compute request MAC: {error}"))
        })?;
        request.extend_from_slice(HEADER_SESSION.as_bytes());
        request.extend_from_slice(b": ");
        request.extend_from_slice(hex::encode(keys.session_id()).as_bytes());
        request.extend_from_slice(b"\r\n");
        request.extend_from_slice(HEADER_SEQ.as_bytes());
        request.extend_from_slice(b": ");
        request.extend_from_slice(auth.seq.to_string().as_bytes());
        request.extend_from_slice(b"\r\n");
        request.extend_from_slice(HEADER_MAC.as_bytes());
        request.extend_from_slice(b": ");
        request.extend_from_slice(hex::encode(mac).as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");

    let mut writer = Writer::new(stream);
    writer
        .write_all(&request)
        .map_err(|error| WireFailure::Transport(format!("request head: {error}")))?;
    if let Some((kind, meta)) = frame {
        let header = Header::new(
            kind,
            u32::try_from(meta.len())
                .map_err(|_| WireFailure::Protocol("request meta is too large".to_owned()))?,
            data_len,
            limits,
        )
        .map_err(WireFailure::from_proto)?;
        writer
            .write_all(&header.encode())
            .map_err(|error| WireFailure::Transport(format!("frame header: {error}")))?;
        writer
            .write_all(meta)
            .map_err(|error| WireFailure::Transport(format!("frame meta: {error}")))?;
        if let Some(plan) = payload {
            plan.write_to(&mut writer.sink)
                .map_err(|error| WireFailure::Transport(format!("frame payload: {error}")))?;
        }
    }
    writer
        .flush()
        .map_err(|error| WireFailure::Transport(format!("request flush: {error}")))?;

    read_response(writer.into_inner())
}

/// A buffered writer that counts and keeps the stream for the read half.
struct Writer {
    sink: BufWriter,
}

struct BufWriter {
    stream: TcpStream,
}

impl Writer {
    fn new(stream: TcpStream) -> Self {
        Self {
            sink: BufWriter { stream },
        }
    }

    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.sink.stream.write_all(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sink.stream.flush()
    }

    fn into_inner(self) -> TcpStream {
        self.sink.stream
    }
}

impl Write for BufWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

fn connect(addrs: &[SocketAddr], timeout: Duration) -> Result<TcpStream, WireFailure> {
    let mut last = String::from("no address");
    for addr in addrs {
        match TcpStream::connect_timeout(addr, timeout) {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(error) => last = format!("{addr}: {error}"),
        }
    }
    Err(WireFailure::Transport(format!("cannot connect: {last}")))
}

fn read_response(stream: TcpStream) -> Result<WireResponse, WireFailure> {
    let mut reader = BufReader::new(stream);
    let status_line = read_line(&mut reader)?;
    let mut parts = status_line.split_whitespace();
    let _version = parts
        .next()
        .ok_or_else(|| WireFailure::Protocol("empty HTTP status line".to_owned()))?;
    let status = parts
        .next()
        .ok_or_else(|| WireFailure::Protocol("missing HTTP status".to_owned()))?
        .parse::<u16>()
        .map_err(|_| WireFailure::Protocol(format!("bad HTTP status line `{status_line}`")))?;

    let mut headers = BTreeMap::new();
    loop {
        let line = read_line(&mut reader)?;
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| WireFailure::Protocol(format!("bad HTTP header `{line}`")))?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }

    let body = if headers
        .get("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        read_chunked(&mut reader)?
    } else if let Some(length) = headers.get("content-length") {
        let length = length
            .parse::<usize>()
            .map_err(|_| WireFailure::Protocol(format!("bad content length `{length}`")))?;
        let mut body = vec![0u8; length];
        reader
            .read_exact(&mut body)
            .map_err(|error| WireFailure::Transport(format!("response body: {error}")))?;
        body
    } else if status == 204 || status == 304 {
        Vec::new()
    } else {
        let mut body = Vec::new();
        reader
            .read_to_end(&mut body)
            .map_err(|error| WireFailure::Transport(format!("response body: {error}")))?;
        body
    };

    Ok(WireResponse {
        status,
        headers,
        body,
    })
}

fn read_line(reader: &mut BufReader<TcpStream>) -> Result<String, WireFailure> {
    let mut line = String::new();
    let read = reader
        .read_line(&mut line)
        .map_err(|error| WireFailure::Transport(format!("response line: {error}")))?;
    if read == 0 {
        return Err(WireFailure::Transport(
            "connection closed before a response line".to_owned(),
        ));
    }
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(line)
}

fn read_chunked(reader: &mut BufReader<TcpStream>) -> Result<Vec<u8>, WireFailure> {
    let mut body = Vec::new();
    loop {
        let line = read_line(reader)?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| WireFailure::Protocol(format!("bad chunk size `{line}`")))?;
        if size == 0 {
            loop {
                let trailer = read_line(reader)?;
                if trailer.is_empty() {
                    break;
                }
            }
            return Ok(body);
        }
        let start = body.len();
        body.resize(start + size, 0);
        reader
            .read_exact(&mut body[start..])
            .map_err(|error| WireFailure::Transport(format!("chunk: {error}")))?;
        let mut crlf = [0u8; 2];
        reader
            .read_exact(&mut crlf)
            .map_err(|error| WireFailure::Transport(format!("chunk terminator: {error}")))?;
        if crlf != *b"\r\n" {
            return Err(WireFailure::Protocol(
                "chunk is not followed by CRLF".to_owned(),
            ));
        }
    }
}
