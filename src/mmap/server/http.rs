//! HTTP/1.1 listener, exact routes, SMM1 framing and response bodies.
//!
//! The listener accepts one namespace and routes only:
//!
//! ```text
//! POST {ns}/mm/v1/hello          unauthenticated
//! POST {ns}/mm/v1/checkout       authenticated
//! POST {ns}/mm/v1/file/read      authenticated
//! POST {ns}/mm/v1/signatures     authenticated
//! POST {ns}/mm/v1/upload/begin   authenticated
//! POST {ns}/mm/v1/upload/commit  authenticated, payload is instructions
//! POST {ns}/mm/v1/upload/abort   authenticated
//! POST {ns}/mm/v1/lock/acquire   authenticated
//! POST {ns}/mm/v1/lock/renew     authenticated
//! POST {ns}/mm/v1/lock/release   authenticated
//! GET  {ns}/mm/v1/batch/{id}     authenticated
//! GET  {ns}/mm/v1/version?dir_ino=...
//! GET  /__syncmount/healthz      fixed JSON, no auth
//! ```
//!
//! A request body is scanned once: the 24-byte header, the meta stream and the
//! payload are separated while they arrive, and the payload is spooled instead
//! of buffered. The MAC is checked after the last payload byte, before any
//! semantic work.

use std::convert::Infallible;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::header::{self, HeaderValue};
use http::{HeaderMap, Method, Request, Response as HttpResponse, StatusCode};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use crate::mmap::db::MmTx;
use crate::mmap::proto::{
    Checkout, ErrorBody, ErrorCode, FileRead, HEADER_LEN, Header, Limits, Message, UploadAbort,
    UploadBegin, UploadCommit, decode_frame,
};
use crate::transport::BODY_QUEUE_DEPTH;
use crate::transport::body::{BodyError, BodyStream, MpscBody};

use super::spool::TempPayload;
use super::{Fault, ServerState};

/// The response body type.
pub enum MmBody {
    /// A complete body.
    Full(Option<Bytes>),
    /// A response streamed through a bounded channel.
    Stream(MpscBody),
}

impl std::fmt::Debug for MmBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full(bytes) => f.debug_tuple("Full").field(bytes).finish(),
            Self::Stream(body) => f.debug_tuple("Stream").field(body).finish(),
        }
    }
}

impl Body for MmBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Full(slot) => Poll::Ready(slot.take().map(|bytes| Ok(Frame::data(bytes)))),
            Self::Stream(body) => Pin::new(body).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Full(slot) => slot.is_none(),
            Self::Stream(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Full(Some(bytes)) => SizeHint::with_exact(bytes.len() as u64),
            Self::Full(None) => SizeHint::with_exact(0),
            Self::Stream(body) => body.size_hint(),
        }
    }
}

/// One HTTP response with an mm body.
pub type Response = HttpResponse<MmBody>;

/// Headers carried by an authenticated request.
#[derive(Clone, Debug, Default)]
pub struct Credentials {
    /// `X-SM-MM-Session`, hex.
    pub session: Option<String>,
    /// `X-SM-MM-Seq`, decimal.
    pub seq: Option<String>,
    /// `X-SM-MM-MAC`, hex.
    pub mac: Option<String>,
}

impl Credentials {
    /// Read the three headers; missing values are kept as `None` so the
    /// authentication layer can answer with the specific `AUTH_FAILED`.
    pub fn from_headers(headers: &HeaderMap) -> Self {
        Self {
            session: header_text(headers, crate::mmap::proto::HEADER_SESSION),
            seq: header_text(headers, crate::mmap::proto::HEADER_SEQ),
            mac: header_text(headers, crate::mmap::proto::HEADER_MAC),
        }
    }
}

fn header_text(headers: &HeaderMap, name: &'static str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// One frame whose meta is in memory and whose payload may be spooled.
#[derive(Debug)]
pub struct ReceivedFrame {
    /// The SMM1 header.
    pub header: Header,
    /// The tagged meta stream.
    pub meta: Vec<u8>,
    /// BLAKE3 of the meta bytes.
    pub meta_hash: [u8; 32],
    /// BLAKE3 of the payload bytes.
    pub payload_hash: [u8; 32],
    /// Payload bytes received.
    pub payload_len: u64,
    /// Payload spool path, when one was requested and bytes arrived.
    pub payload_path: Option<PathBuf>,
}

impl ReceivedFrame {
    /// Reject a request that must not carry a payload.
    pub fn expect_no_payload(&self) -> Result<(), Fault> {
        if self.payload_len == 0 {
            Ok(())
        } else {
            Err(Fault::detail(
                ErrorCode::BadRequest,
                "request carries an unexpected payload",
            ))
        }
    }
}

/// Route table entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    Hello,
    Checkout,
    FileRead,
    Signatures,
    UploadBegin,
    UploadCommit,
    UploadAbort,
    LockAcquire,
    LockRenew,
    LockRelease,
    Batch([u8; 16]),
    Version([u8; 16]),
}

/// Serve one accepted TCP connection.
pub async fn serve_connection(state: Arc<ServerState>, stream: TcpStream) {
    let io = TokioIo::new(stream);
    let service = service_fn(move |request: Request<Incoming>| {
        let state = Arc::clone(&state);
        async move { Ok::<_, Infallible>(handle(state, request).await) }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .keep_alive(true)
        .serve_connection(io, service)
        .await;
}

/// Handle one request.
pub async fn handle(state: Arc<ServerState>, request: Request<Incoming>) -> Response {
    match handle_inner(state, request).await {
        Ok(response) => response,
        Err(fault) => error_response(fault),
    }
}

async fn handle_inner(
    state: Arc<ServerState>,
    request: Request<Incoming>,
) -> Result<Response, Fault> {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path().to_owned();
    let mac_path = uri
        .path_and_query()
        .map(|value| value.as_str().to_owned())
        .unwrap_or_else(|| path.clone());

    if path == crate::transport::HEALTHZ_PATH {
        if method == Method::GET {
            return Ok(healthz(&state));
        }
        return Ok(text_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed",
        ));
    }

    let Some(route) = route(state.config(), &path, uri.query()) else {
        return Ok(text_response(StatusCode::NOT_FOUND, "not found"));
    };

    match (method, route) {
        (Method::GET, Route::Batch(batch_id)) => {
            let credentials = Credentials::from_headers(request.headers());
            state.authenticate_empty("GET", &mac_path, &credentials)?;
            state.batch_status(batch_id)
        }
        (Method::GET, Route::Version(dir_ino)) => {
            let credentials = Credentials::from_headers(request.headers());
            state.authenticate_empty("GET", &mac_path, &credentials)?;
            state.dir_version(dir_ino)
        }
        (Method::POST, Route::Hello) => {
            let received = receive_frame(
                BodyStream::new(request.into_body()),
                &state.config().limits,
                None,
                false,
            )
            .await?;
            received.expect_no_payload()?;
            state.hello(&received)
        }
        (Method::POST, route) => {
            let credentials = Credentials::from_headers(request.headers());
            let spill = if route == Route::UploadCommit {
                Some(state.spool().tmp_path())
            } else {
                None
            };
            let guard = spill.clone().map(TempPayload::new);
            let received = receive_frame(
                BodyStream::new(request.into_body()),
                &state.config().limits,
                spill.as_deref(),
                route == Route::UploadCommit,
            )
            .await?;
            let session = state.authenticate_frame("POST", &mac_path, &credentials, &received)?;
            match route {
                Route::Checkout => {
                    received.expect_no_payload()?;
                    let message: Checkout = decode_frame(&received.header, &received.meta)?;
                    state.checkout(message).await
                }
                Route::FileRead => {
                    received.expect_no_payload()?;
                    let message: FileRead = decode_frame(&received.header, &received.meta)?;
                    state.file_read(message)
                }
                Route::Signatures => {
                    received.expect_no_payload()?;
                    let message: crate::mmap::proto::SignatureRequest =
                        decode_frame(&received.header, &received.meta)?;
                    state.signatures(message, session)
                }
                Route::UploadBegin => {
                    received.expect_no_payload()?;
                    let message: UploadBegin = decode_frame(&received.header, &received.meta)?;
                    state.upload_begin(message, session).await
                }
                Route::UploadCommit => {
                    let message: UploadCommit = decode_frame(&received.header, &received.meta)?;
                    let payload = guard.as_ref().map(TempPayload::path);
                    state.upload_commit(message, session, payload).await
                }
                Route::UploadAbort => {
                    received.expect_no_payload()?;
                    let message: UploadAbort = decode_frame(&received.header, &received.meta)?;
                    state.upload_abort(message, session).await
                }
                Route::LockAcquire => {
                    received.expect_no_payload()?;
                    let message: crate::mmap::proto::LockAcquire =
                        decode_frame(&received.header, &received.meta)?;
                    state.lock_acquire(message, session).await
                }
                Route::LockRenew => {
                    received.expect_no_payload()?;
                    let message: crate::mmap::proto::LockRenew =
                        decode_frame(&received.header, &received.meta)?;
                    state.lock_renew(message, session).await
                }
                Route::LockRelease => {
                    received.expect_no_payload()?;
                    let message: crate::mmap::proto::LockRelease =
                        decode_frame(&received.header, &received.meta)?;
                    state.lock_release(message, session).await
                }
                Route::Hello | Route::Batch(_) | Route::Version(_) => Ok(text_response(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method not allowed",
                )),
            }
        }
        (_, Route::Batch(_) | Route::Version(_)) => Ok(text_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed",
        )),
        _ => Ok(text_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed",
        )),
    }
}

fn route(config: &super::MmapConfig, path: &str, query: Option<&str>) -> Option<Route> {
    let base = format!("{}/mm/v1", config.namespace);
    if path == format!("{base}/hello") {
        return Some(Route::Hello);
    }
    if path == format!("{base}/checkout") {
        return Some(Route::Checkout);
    }
    if path == format!("{base}/file/read") {
        return Some(Route::FileRead);
    }
    if path == format!("{base}/signatures") {
        return Some(Route::Signatures);
    }
    if path == format!("{base}/upload/begin") {
        return Some(Route::UploadBegin);
    }
    if path == format!("{base}/upload/commit") {
        return Some(Route::UploadCommit);
    }
    if path == format!("{base}/upload/abort") {
        return Some(Route::UploadAbort);
    }
    if path == format!("{base}/lock/acquire") {
        return Some(Route::LockAcquire);
    }
    if path == format!("{base}/lock/renew") {
        return Some(Route::LockRenew);
    }
    if path == format!("{base}/lock/release") {
        return Some(Route::LockRelease);
    }
    if path == format!("{base}/version") {
        let value = query_param(query?, "dir_ino")?;
        return Some(Route::Version(parse_hex16(value)?));
    }
    let batch_prefix = format!("{base}/batch/");
    if let Some(rest) = path.strip_prefix(&batch_prefix) {
        if !rest.is_empty() && !rest.contains('/') {
            return Some(Route::Batch(parse_hex16(rest)?));
        }
    }
    None
}

fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key).then_some(value)
    })
}

fn parse_hex16(value: &str) -> Option<[u8; 16]> {
    let bytes = hex::decode(value).ok()?;
    bytes.try_into().ok()
}

/// Read one SMM1 frame from an HTTP body.
///
/// The header and meta are bounded and kept in memory. Payload bytes are
/// hashed and, when `spill` is set, appended to that file.
pub async fn receive_frame(
    mut body: BodyStream<Incoming>,
    limits: &Limits,
    spill: Option<&Path>,
    allow_payload: bool,
) -> Result<ReceivedFrame, Fault> {
    let mut prefix = Vec::with_capacity(HEADER_LEN);
    let mut header: Option<Header> = None;
    let mut meta = Vec::new();
    let mut meta_hasher = blake3::Hasher::new();
    let mut payload_hasher = blake3::Hasher::new();
    let mut payload_len = 0u64;
    let mut file: Option<std::fs::File> = None;

    loop {
        let chunk = match body.next_bytes().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(error) => {
                return Err(Fault::detail(
                    ErrorCode::BadRequest,
                    format!("request body: {error}"),
                ));
            }
        };
        let mut bytes: &[u8] = chunk.as_ref();
        if header.is_none() {
            let take = (HEADER_LEN - prefix.len()).min(bytes.len());
            prefix.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if prefix.len() == HEADER_LEN {
                let decoded = Header::decode_with_limits(&prefix, limits)?;
                if !allow_payload && decoded.data_len != 0 {
                    return Err(Fault::detail(
                        ErrorCode::BadRequest,
                        "request carries an unexpected payload",
                    ));
                }
                header = Some(decoded);
            }
        }
        let Some(decoded) = header else {
            continue;
        };
        if bytes.is_empty() {
            continue;
        }
        if meta.len() < decoded.meta_len as usize {
            let take = (decoded.meta_len as usize - meta.len()).min(bytes.len());
            meta.extend_from_slice(&bytes[..take]);
            meta_hasher.update(&bytes[..take]);
            bytes = &bytes[take..];
        }
        if bytes.is_empty() {
            continue;
        }
        let next = payload_len
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| Fault::detail(ErrorCode::BadRequest, "payload overflows"))?;
        if next > decoded.data_len {
            return Err(Fault::detail(
                ErrorCode::BadRequest,
                "payload exceeds data_len",
            ));
        }
        if let Some(path) = spill {
            if file.is_none() {
                file = Some(std::fs::File::create(path).map_err(Fault::from)?);
            }
        }
        if let Some(handle) = file.as_mut() {
            handle.write_all(bytes)?;
        }
        payload_hasher.update(bytes);
        payload_len = next;
    }

    let Some(header) = header else {
        return Err(Fault::detail(
            ErrorCode::BadRequest,
            "request ends inside the SMM1 header",
        ));
    };
    if meta.len() != header.meta_len as usize {
        return Err(Fault::detail(
            ErrorCode::BadRequest,
            "request ends inside the SMM1 meta stream",
        ));
    }
    if payload_len != header.data_len {
        return Err(Fault::detail(
            ErrorCode::BadRequest,
            "request ends inside the SMM1 payload",
        ));
    }
    if let Some(mut handle) = file {
        handle.flush()?;
        handle.sync_data()?;
    }

    Ok(ReceivedFrame {
        header,
        meta_hash: *meta_hasher.finalize().as_bytes(),
        payload_hash: *payload_hasher.finalize().as_bytes(),
        payload_len,
        payload_path: file_path(spill, payload_len),
        meta,
    })
}

fn file_path(spill: Option<&Path>, payload_len: u64) -> Option<PathBuf> {
    if payload_len == 0 {
        None
    } else {
        spill.map(Path::to_path_buf)
    }
}

/// Encode a message header and meta for a response with `data_len`.
pub fn encode_head<M: Message>(
    message: &M,
    data_len: u64,
    limits: &Limits,
) -> Result<(Header, Vec<u8>), Fault> {
    let meta = message.encode_meta()?;
    let meta_len = u32::try_from(meta.len())
        .map_err(|_| Fault::detail(ErrorCode::TooLarge, "response meta is too large"))?;
    let header = Header::new(M::KIND, meta_len, data_len, limits)?;
    Ok((header, meta))
}

/// A complete frame response.
pub fn bytes_response<M: Message>(message: &M, payload: &[u8]) -> Result<Response, Fault> {
    let (header, meta) = encode_head(message, payload.len() as u64, &Limits::new())?;
    let mut bytes = Vec::with_capacity(HEADER_LEN + meta.len() + payload.len());
    bytes.extend_from_slice(&header.encode());
    bytes.extend_from_slice(&meta);
    bytes.extend_from_slice(payload);
    Ok(full_response(200, bytes))
}

/// A response with no payload.
pub fn message_response<M: Message>(message: &M) -> Result<Response, Fault> {
    bytes_response(message, &[])
}

/// A complete response body.
pub fn full_response(status: u16, bytes: Vec<u8>) -> Response {
    response(
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        MmBody::Full(Some(Bytes::from(bytes))),
    )
}

/// A response with no body and no mm framing.
pub fn empty_response(status: u16) -> Response {
    response(
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        MmBody::Full(None),
    )
}

/// A response with a bounded streaming body.
pub fn stream_response(status: u16, body: MpscBody) -> Response {
    let mut response = response(
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        MmBody::Stream(body),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        http::header::HeaderName::from_static("x-accel-buffering"),
        HeaderValue::from_static("no"),
    );
    let _ = BODY_QUEUE_DEPTH;
    response
}

/// A `304 Not Modified` carrying the current base in headers.
pub fn not_modified(fields: &[(&'static str, String)]) -> Response {
    let mut response = empty_response(304);
    for (name, value) in fields {
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}

fn response(status: StatusCode, body: MmBody) -> Response {
    let mut response = HttpResponse::new(body);
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-syncmount-mm"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn text_response(status: StatusCode, text: &str) -> Response {
    let mut response = response(status, MmBody::Full(Some(Bytes::from(text.to_owned()))));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn healthz(state: &ServerState) -> Response {
    let (seq, locks) = match state.read() {
        Ok(tx) => {
            let seq = tx.mm_seq().map(|seq| seq.get()).unwrap_or(0);
            let locks = tx
                .conn()
                .query_row("SELECT COUNT(*) FROM mm_locks", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap_or(0);
            (seq, locks)
        }
        Err(_) => (0, 0),
    };
    let body = format!(
        r#"{{"status":"ok","version":"{}","mode":"mmap","namespace":"{}","snapshot_seq":{},"sessions":{},"locks":{}}}"#,
        env!("CARGO_PKG_VERSION"),
        state.config().namespace,
        seq,
        state.session_count(),
        locks,
    );
    let mut response = response(StatusCode::OK, MmBody::Full(Some(Bytes::from(body))));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

/// Convert a fault into a terminal `ERROR` frame and its HTTP status.
pub fn error_response(fault: Fault) -> Response {
    let status = fault.status();
    let body: ErrorBody = fault.body;
    match encode_head(&body, 0, &Limits::new()) {
        Ok((header, meta)) => {
            let mut bytes = Vec::with_capacity(HEADER_LEN + meta.len());
            bytes.extend_from_slice(&header.encode());
            bytes.extend_from_slice(&meta);
            full_response(status, bytes)
        }
        Err(_) => text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot encode the error response",
        ),
    }
}

#[cfg(all(test, feature = "mmap-tests"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::mmap::proto::{Kind, Limits};

    #[test]
    fn routes_are_exact_and_batch_ids_are_hex() {
        let config = crate::mmap::server::MmapConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            "/p",
            "/tmp/x.db",
            "/tmp/x",
            [0; 32],
        );
        assert_eq!(route(&config, "/p/mm/v1/hello", None), Some(Route::Hello));
        assert_eq!(route(&config, "/p2/mm/v1/hello", None), None);
        assert_eq!(route(&config, "/p/mm/v1/hello/x", None), None);
        let id = [0xAB; 16];
        assert_eq!(
            route(
                &config,
                &format!("/p/mm/v1/batch/{}", hex::encode(id)),
                None
            ),
            Some(Route::Batch(id))
        );
        assert_eq!(route(&config, "/p/mm/v1/version?dir_ino=zz", None), None);
        assert_eq!(
            route(
                &config,
                "/p/mm/v1/version",
                Some("dir_ino=00000000000000000000000000000000")
            ),
            Some(Route::Version([0; 16]))
        );
    }

    #[test]
    fn response_has_the_expected_content_type() {
        let response = full_response(200, vec![1, 2, 3]);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/x-syncmount-mm"
        );
    }

    #[test]
    fn head_encoding_uses_the_message_kind_and_payload_length() {
        let data = crate::mmap::proto::FileData {
            range_offset: 3,
            range_len: 2,
            range_hash: [4; 32],
        };
        let (header, meta) = encode_head(&data, 2, &Limits::new()).unwrap();
        assert_eq!(header.kind, Kind::FileData);
        assert_eq!(header.data_len, 2);
        assert_eq!(header.meta_len as usize, meta.len());
    }
}
