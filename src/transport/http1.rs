//! Production HTTP/1.1 transport over hyper.
//!
//! Client side: [`HttpTransport`] dials both halves of a session (or
//! [`HttpDialer`] dials one half at a time). Server side: [`HttpAcceptor`]
//! accepts TCP connections, routes exactly three paths, and hands streaming
//! bodies to the server layer:
//!
//! | method | path | result |
//! |---|---|---|
//! | POST | `{prefix}/rpc` | [`AcceptedHttp::Rpc`], request body streamed |
//! | GET | `{prefix}/events` | [`AcceptedHttp::Events`], response body streamed |
//! | GET | `/__syncmount/healthz` | fixed JSON, handled here |
//!
//! Everything else is a 404. Matching is exact; `/sync2/rpc` never reaches a
//! `/sync` handler (24 §1.3).
//!
//! HTTP/1.1 only. No Upgrade, no WebSocket, no HTTP/2: the protocol already
//! has its own flow control and adding another layer would make backpressure
//! impossible to reason about (42 §7.1).
//!
//! The downlink response carries `X-Accel-Buffering: no` and
//! `Cache-Control: no-store` before its first byte, because a reverse proxy
//! that buffers an infinite chunked body would turn a live stream into a
//! dead one (24 §6.1).
//!
//! Every accepted and dialed socket enables TCP keepalive, so the kernel
//! reports a half-open connection instead of leaving the stream silent.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{self, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

use super::body::{BodyError, BodyStream, MpscBody, MpscSender};
use super::endpoint::{
    CLIENT_ID_HEADER, EVENTS_SUFFIX, Endpoint, HEALTHZ_PATH, NONCE_HEADER, RPC_SUFFIX, child_path,
    client_id_from_headers, client_id_header, nonce_from_headers, nonce_header, normalize_prefix,
};
use super::{
    BODY_QUEUE_DEPTH, BoxFut, DialOptions, Dialer, PeerId, StreamKind, Transport, TransportError,
};

/// TCP keepalive idle time before the first probe.
pub const KEEPALIVE_TIME: Duration = Duration::from_secs(60);
/// TCP keepalive probe interval.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// Failed probes before the kernel reports the connection dead.
pub const KEEPALIVE_RETRIES: u32 = 3;

/// Enable keepalive on `stream` with the constants above.
fn configure_keepalive(stream: &TcpStream) -> Result<(), TransportError> {
    rustix::net::sockopt::set_socket_keepalive(stream, true).map_err(std::io::Error::from)?;
    rustix::net::sockopt::set_tcp_keepidle(stream, KEEPALIVE_TIME).map_err(std::io::Error::from)?;
    rustix::net::sockopt::set_tcp_keepintvl(stream, KEEPALIVE_INTERVAL)
        .map_err(std::io::Error::from)?;
    rustix::net::sockopt::set_tcp_keepcnt(stream, KEEPALIVE_RETRIES)
        .map_err(std::io::Error::from)?;
    Ok(())
}

/// Reason a logical session ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CloseReason {
    /// Local `close()`.
    Local,
    /// Peer ended the stream without an error.
    Remote,
    /// Socket, protocol or status failure.
    Failed,
}

/// Session-wide state shared by both halves.
///
/// One dead half ends the session: HTTP/1.1 has no way to resume a single
/// stream, and the protocol has no replay window.
#[derive(Debug)]
struct ConnState {
    closed: watch::Sender<Option<CloseReason>>,
}

impl ConnState {
    fn new() -> Arc<Self> {
        let (closed, _receiver) = watch::channel(None);
        Arc::new(Self { closed })
    }

    fn mark(&self, reason: CloseReason) {
        let open = self.closed.borrow().is_none();
        if open {
            self.closed.send_replace(Some(reason));
        }
    }

    fn reason(&self) -> Option<CloseReason> {
        *self.closed.borrow()
    }

    fn subscribe(&self) -> watch::Receiver<Option<CloseReason>> {
        self.closed.subscribe()
    }
}

/// Request body for the downlink: always empty, exactly zero bytes.
#[derive(Clone, Copy, Debug, Default)]
struct EmptyBody;

impl Body for EmptyBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        true
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(0)
    }
}

/// Uplink half of a session.
#[derive(Debug)]
pub struct RpcStream {
    body: MpscSender,
    state: Arc<ConnState>,
    response: Option<JoinHandle<()>>,
    connection: Option<JoinHandle<()>>,
}

impl RpcStream {
    fn shutdown(&mut self) {
        self.state.mark(CloseReason::Local);
        self.body.close();
        if let Some(task) = self.response.take() {
            task.abort();
        }
        if let Some(task) = self.connection.take() {
            task.abort();
        }
    }
}

impl Transport for RpcStream {
    fn send(&mut self, chunk: Bytes) -> BoxFut<'_, Result<(), TransportError>> {
        Box::pin(async move {
            if self.state.reason().is_some() {
                return Err(TransportError::Disconnected);
            }
            match self.body.send(chunk).await {
                Ok(()) => Ok(()),
                Err(_) => {
                    self.state.mark(CloseReason::Failed);
                    Err(TransportError::Disconnected)
                }
            }
        })
    }

    fn recv(&mut self) -> BoxFut<'_, Result<Option<Bytes>, TransportError>> {
        Box::pin(async move {
            // The server answers the POST only when the session ends, so this
            // is exactly the "server closed the uplink" edge.
            if let Some(task) = self.response.take() {
                let _ = task.await;
            }
            match self.state.reason() {
                Some(CloseReason::Failed) => Err(TransportError::Disconnected),
                _ => Ok(None),
            }
        })
    }

    fn close(&mut self) -> BoxFut<'_, Result<(), TransportError>> {
        Box::pin(async move {
            self.shutdown();
            Ok(())
        })
    }
}

/// Downlink half of a session.
#[derive(Debug)]
pub struct EventsStream {
    body: BodyStream<Incoming>,
    sender: Option<hyper::client::conn::http1::SendRequest<EmptyBody>>,
    state: Arc<ConnState>,
    state_rx: watch::Receiver<Option<CloseReason>>,
    connection: Option<JoinHandle<()>>,
}

impl EventsStream {
    /// One poll after either half closed.
    ///
    /// The final frames (`KICK`, `SYNC_END`) travel on the events body after
    /// the RPC half ends. A zero-timeout poll would discard a chunk that is
    /// still in flight, so the drain gives the body a bounded grace and keeps
    /// returning buffered chunks until the body ends.
    async fn drain_closed(&mut self, failed: bool) -> Result<Option<Bytes>, TransportError> {
        const GRACE: std::time::Duration = std::time::Duration::from_secs(1);
        match tokio::time::timeout(GRACE, self.body.next_bytes()).await {
            Ok(Ok(Some(chunk))) => Ok(Some(chunk)),
            Ok(Ok(None)) if failed => Err(TransportError::Disconnected),
            Ok(Ok(None)) => Ok(None),
            Ok(Err(error)) => {
                self.state.mark(CloseReason::Failed);
                Err(TransportError::Hyper(error))
            }
            Err(_elapsed) if failed => Err(TransportError::Disconnected),
            Err(_elapsed) => Ok(None),
        }
    }
}

impl Transport for EventsStream {
    fn send(&mut self, _chunk: Bytes) -> BoxFut<'_, Result<(), TransportError>> {
        Box::pin(async move { Err(TransportError::WrongDirection(StreamKind::Events, "send")) })
    }

    fn recv(&mut self) -> BoxFut<'_, Result<Option<Bytes>, TransportError>> {
        Box::pin(async move {
            loop {
                match self.state.reason() {
                    Some(CloseReason::Failed) => return self.drain_closed(true).await,
                    Some(CloseReason::Local) => return Ok(None),
                    Some(CloseReason::Remote) => return self.drain_closed(false).await,
                    None => {}
                }
                tokio::select! {
                    biased;
                    next = self.body.next_bytes() => match next {
                        Ok(Some(chunk)) => return Ok(Some(chunk)),
                        Ok(None) => {
                            self.state.mark(CloseReason::Remote);
                            return Ok(None);
                        }
                        Err(error) => {
                            self.state.mark(CloseReason::Failed);
                            return Err(TransportError::Hyper(error));
                        }
                    },
                    changed = self.state_rx.changed() => {
                        if changed.is_err() {
                            return Err(TransportError::Disconnected);
                        }
                    }
                }
            }
        })
    }

    fn close(&mut self) -> BoxFut<'_, Result<(), TransportError>> {
        Box::pin(async move {
            self.state.mark(CloseReason::Local);
            self.sender.take();
            if let Some(task) = self.connection.take() {
                task.abort();
            }
            Ok(())
        })
    }
}

/// Dual-stream client connection.
///
/// Dials the downlink first (24 §4.1), then the uplink, sharing one nonce.
/// Either half closing ends the logical session.
#[derive(Debug)]
pub struct HttpTransport {
    rpc: RpcStream,
    events: EventsStream,
}

impl HttpTransport {
    /// Dial both halves of a session.
    pub async fn dial(endpoint: &Endpoint, options: &DialOptions) -> Result<Self, TransportError> {
        if endpoint.is_tls() {
            return Err(TransportError::TlsUnsupported);
        }
        let state = ConnState::new();
        let events = dial_events(endpoint, options, Arc::clone(&state)).await?;
        let rpc = dial_rpc(endpoint, options, state).await?;
        Ok(Self { rpc, events })
    }

    /// Write bytes to the uplink.
    pub async fn send(&mut self, chunk: Bytes) -> Result<(), TransportError> {
        self.rpc.send(chunk).await
    }

    /// Read bytes from the downlink.
    pub async fn recv(&mut self) -> Result<Option<Bytes>, TransportError> {
        self.events.recv().await
    }

    /// Close both halves. Idempotent at the session level.
    pub async fn close(mut self) -> Result<(), TransportError> {
        self.rpc.close().await?;
        self.events.close().await
    }

    /// Split into independently owned halves for two tasks.
    pub fn split(self) -> (RpcStream, EventsStream) {
        (self.rpc, self.events)
    }
}

/// Stateless dialer for one stream at a time.
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpDialer;

impl HttpDialer {
    /// New dialer.
    pub const fn new() -> Self {
        Self
    }
}

impl Dialer for HttpDialer {
    fn dial<'a>(
        &'a self,
        endpoint: &'a Endpoint,
        kind: StreamKind,
        options: &'a DialOptions,
    ) -> BoxFut<'a, Result<Box<dyn Transport>, TransportError>> {
        Box::pin(async move {
            if endpoint.is_tls() {
                return Err(TransportError::TlsUnsupported);
            }
            let state = ConnState::new();
            match kind {
                StreamKind::Rpc => {
                    Ok(Box::new(dial_rpc(endpoint, options, state).await?) as Box<dyn Transport>)
                }
                StreamKind::Events => {
                    Ok(Box::new(dial_events(endpoint, options, state).await?)
                        as Box<dyn Transport>)
                }
            }
        })
    }
}

fn request_builder(
    endpoint: &Endpoint,
    kind: StreamKind,
    options: &DialOptions,
) -> Result<http::request::Builder, TransportError> {
    let uri = match kind {
        StreamKind::Rpc => endpoint.rpc_uri(),
        StreamKind::Events => endpoint.events_uri(),
    };
    // hyper writes the URI exactly as given. Origin-form keeps the wire
    // request free of an authority that reverse proxies might rewrite; the
    // authority lives in the Host header below (RFC 9112 §3.2.1).
    let target = uri.path_and_query().map_or("/", |pq| pq.as_str());
    let mut builder = Request::builder()
        .uri(target)
        .header(header::HOST, endpoint.authority().as_str())
        .header(NONCE_HEADER, nonce_header(options.nonce)?);
    if let Some(client_id) = options.client_id {
        builder = builder.header(CLIENT_ID_HEADER, client_id_header(client_id)?);
    }
    Ok(builder)
}

async fn connect(endpoint: &Endpoint) -> Result<TcpStream, TransportError> {
    let stream = TcpStream::connect((endpoint.host(), endpoint.port())).await?;
    stream.set_nodelay(true)?;
    configure_keepalive(&stream)?;
    Ok(stream)
}

async fn dial_rpc(
    endpoint: &Endpoint,
    options: &DialOptions,
    state: Arc<ConnState>,
) -> Result<RpcStream, TransportError> {
    let stream = connect(endpoint).await?;
    let io = TokioIo::new(stream);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });

    let (body_tx, body) = MpscBody::channel(BODY_QUEUE_DEPTH);
    let request = request_builder(endpoint, StreamKind::Rpc, options)?
        .method(Method::POST)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(body)
        .map_err(|error| TransportError::Http(error.to_string()))?;

    if let Err(error) = sender.ready().await {
        connection_task.abort();
        return Err(TransportError::Hyper(error));
    }

    let task_state = Arc::clone(&state);
    let response_task = tokio::spawn(async move {
        match sender.send_request(request).await {
            Ok(response) if response.status().is_success() => {
                task_state.mark(CloseReason::Remote);
            }
            Ok(_) | Err(_) => task_state.mark(CloseReason::Failed),
        }
    });

    Ok(RpcStream {
        body: body_tx,
        state,
        response: Some(response_task),
        connection: Some(connection_task),
    })
}

async fn dial_events(
    endpoint: &Endpoint,
    options: &DialOptions,
    state: Arc<ConnState>,
) -> Result<EventsStream, TransportError> {
    let stream = connect(endpoint).await?;
    let io = TokioIo::new(stream);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = request_builder(endpoint, StreamKind::Events, options)?
        .method(Method::GET)
        .body(EmptyBody)
        .map_err(|error| TransportError::Http(error.to_string()))?;

    if let Err(error) = sender.ready().await {
        connection_task.abort();
        return Err(TransportError::Hyper(error));
    }
    let response = match sender.send_request(request).await {
        Ok(response) => response,
        Err(error) => {
            connection_task.abort();
            return Err(TransportError::Hyper(error));
        }
    };
    if response.status() != StatusCode::OK {
        connection_task.abort();
        return Err(TransportError::Status(response.status()));
    }

    let state_rx = state.subscribe();
    Ok(EventsStream {
        body: BodyStream::new(response.into_body()),
        sender: Some(sender),
        state,
        state_rx,
        connection: Some(connection_task),
    })
}

/// One accepted HTTP request, before any frame is interpreted.
#[derive(Debug)]
pub enum AcceptedHttp {
    /// `POST {prefix}/rpc`: read the request body, then drop `end` to answer
    /// `204 No Content`.
    Rpc {
        /// Diagnostic peer handle.
        peer: PeerId,
        /// `X-SM-Nonce` pairing token.
        nonce: u64,
        /// `X-SM-Client-Id` declaration, if present.
        client_id: Option<[u8; 16]>,
        /// Streaming request body.
        body: BodyStream<Incoming>,
        /// Dropping this ends the HTTP exchange.
        end: oneshot::Sender<()>,
    },
    /// `GET {prefix}/events`: write frames to `out`; dropping it ends the
    /// response body.
    Events {
        /// Diagnostic peer handle.
        peer: PeerId,
        /// `X-SM-Nonce` pairing token.
        nonce: u64,
        /// `X-SM-Client-Id` declaration, if present.
        client_id: Option<[u8; 16]>,
        /// Bounded streaming response body.
        out: MpscSender,
    },
}

impl AcceptedHttp {
    /// Which half of the session this request carries.
    pub fn kind(&self) -> StreamKind {
        match self {
            Self::Rpc { .. } => StreamKind::Rpc,
            Self::Events { .. } => StreamKind::Events,
        }
    }

    /// Pairing token.
    pub fn nonce(&self) -> u64 {
        match self {
            Self::Rpc { nonce, .. } | Self::Events { nonce, .. } => *nonce,
        }
    }

    /// Diagnostic peer handle.
    pub fn peer(&self) -> PeerId {
        match self {
            Self::Rpc { peer, .. } | Self::Events { peer, .. } => *peer,
        }
    }
}

/// Exact route table for one namespace.
#[derive(Clone, Debug)]
struct Routes {
    namespace: String,
    rpc: String,
    events: String,
}

impl Routes {
    fn new(namespace: &str) -> Self {
        Self {
            namespace: namespace.to_owned(),
            rpc: child_path(namespace, RPC_SUFFIX),
            events: child_path(namespace, EVENTS_SUFFIX),
        }
    }
}

type HealthFn = Arc<dyn Fn() -> String + Send + Sync>;

/// Server-side HTTP/1.1 acceptor.
///
/// One TCP connection may carry one request; hyper keeps the connection alive
/// for the lifetime of that request, which is all the protocol needs. The
/// acceptor surfaces requests; session logic, pairing and frame parsing belong
/// to the server layer (W9).
pub struct HttpAcceptor {
    listener: TcpListener,
    routes: Arc<Routes>,
    health: HealthFn,
    request_tx: mpsc::Sender<AcceptedHttp>,
    request_rx: mpsc::Receiver<AcceptedHttp>,
    connections: JoinSet<()>,
    connection_count: Arc<AtomicU64>,
    next_peer: u64,
}

impl std::fmt::Debug for HttpAcceptor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpAcceptor")
            .field("local_addr", &self.listener.local_addr().ok())
            .field("namespace", &self.routes.namespace)
            .field(
                "connections",
                &self.connection_count.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl HttpAcceptor {
    /// Bind and prepare the exact routes for `namespace`.
    pub async fn bind(addr: SocketAddr, namespace: &str) -> Result<Self, TransportError> {
        let namespace = normalize_prefix(namespace)?;
        let listener = TcpListener::bind(addr).await?;
        let (request_tx, request_rx) = mpsc::channel(16);
        Ok(Self {
            listener,
            routes: Arc::new(Routes::new(&namespace)),
            health: Arc::new(default_healthz),
            request_tx,
            request_rx,
            connections: JoinSet::new(),
            connection_count: Arc::new(AtomicU64::new(0)),
            next_peer: 0,
        })
    }

    /// Replace the fixed health JSON. The default reports only `status`,
    /// `version` and `mode`; the server layer supplies the live counters.
    pub fn with_healthz(mut self, health: impl Fn() -> String + Send + Sync + 'static) -> Self {
        self.health = Arc::new(health);
        self
    }

    /// Bound address.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.listener.local_addr()?)
    }

    /// Number of TCP connections accepted so far.
    pub fn connection_count(&self) -> u64 {
        self.connection_count.load(Ordering::Relaxed)
    }

    /// Shared counter, for tests and metrics that outlive the acceptor.
    pub fn connection_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.connection_count)
    }

    /// Wait for the next routed request.
    pub async fn accept_http(&mut self) -> Result<AcceptedHttp, TransportError> {
        loop {
            tokio::select! {
                biased;
                request = self.request_rx.recv() => {
                    return request.ok_or(TransportError::Closed);
                }
                joined = self.connections.join_next(), if !self.connections.is_empty() => {
                    let _ = joined;
                }
                accepted = self.listener.accept() => {
                    let (stream, _addr) = accepted?;
                    stream.set_nodelay(true)?;
                    configure_keepalive(&stream)?;
                    self.connection_count.fetch_add(1, Ordering::Relaxed);
                    self.next_peer = self.next_peer.wrapping_add(1);
                    let peer = PeerId::from_serial(self.next_peer);
                    let routes = Arc::clone(&self.routes);
                    let health = Arc::clone(&self.health);
                    let tx = self.request_tx.clone();
                    let _ = self.connections.spawn(async move {
                        serve_connection(stream, peer, routes, health, tx).await;
                    });
                }
            }
        }
    }
}

fn default_healthz() -> String {
    format!(
        r#"{{"status":"ok","version":"{}","mode":"serve"}}"#,
        env!("CARGO_PKG_VERSION")
    )
}

async fn serve_connection(
    stream: TcpStream,
    peer: PeerId,
    routes: Arc<Routes>,
    health: HealthFn,
    tx: mpsc::Sender<AcceptedHttp>,
) {
    let io = TokioIo::new(stream);
    let service = service_fn(move |request: Request<Incoming>| {
        let routes = Arc::clone(&routes);
        let health = Arc::clone(&health);
        let tx = tx.clone();
        async move { Ok::<_, Infallible>(route(request, peer, &routes, &health, &tx).await) }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .keep_alive(true)
        .serve_connection(io, service)
        .await;
}

async fn route(
    request: Request<Incoming>,
    peer: PeerId,
    routes: &Routes,
    health: &HealthFn,
    tx: &mpsc::Sender<AcceptedHttp>,
) -> Response<ServerBody> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();

    // The management path is matched first and is always prefix-free.
    if path == HEALTHZ_PATH {
        return if method == Method::GET {
            health_response(health)
        } else {
            text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
        };
    }
    if path == routes.rpc {
        return if method == Method::POST {
            accept_rpc(request, peer, tx).await
        } else {
            text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
        };
    }
    if path == routes.events {
        return if method == Method::GET {
            accept_events(request, peer, tx).await
        } else {
            text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
        };
    }
    text_response(StatusCode::NOT_FOUND, "not found")
}

async fn accept_rpc(
    request: Request<Incoming>,
    peer: PeerId,
    tx: &mpsc::Sender<AcceptedHttp>,
) -> Response<ServerBody> {
    let headers = request.headers();
    let nonce = match nonce_from_headers(headers) {
        Ok(nonce) => nonce,
        Err(error) => return text_response(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let client_id = match client_id_from_headers(headers) {
        Ok(client_id) => client_id,
        Err(error) => return text_response(StatusCode::BAD_REQUEST, &error.to_string()),
    };

    let (end, end_rx) = oneshot::channel();
    let accepted = AcceptedHttp::Rpc {
        peer,
        nonce,
        client_id,
        body: BodyStream::new(request.into_body()),
        end,
    };
    if tx.send(accepted).await.is_err() {
        return text_response(StatusCode::SERVICE_UNAVAILABLE, "acceptor closed");
    }
    // The response is not written until the session ends. That is deliberate:
    // the request body is the session's lifetime.
    let _ = end_rx.await;
    response(StatusCode::NO_CONTENT, ServerBody::Empty, None)
}

async fn accept_events(
    request: Request<Incoming>,
    peer: PeerId,
    tx: &mpsc::Sender<AcceptedHttp>,
) -> Response<ServerBody> {
    let headers = request.headers();
    let nonce = match nonce_from_headers(headers) {
        Ok(nonce) => nonce,
        Err(error) => return text_response(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let client_id = match client_id_from_headers(headers) {
        Ok(client_id) => client_id,
        Err(error) => return text_response(StatusCode::BAD_REQUEST, &error.to_string()),
    };

    let (out, body) = MpscBody::channel(BODY_QUEUE_DEPTH);
    let accepted = AcceptedHttp::Events {
        peer,
        nonce,
        client_id,
        out,
    };
    if tx.send(accepted).await.is_err() {
        return text_response(StatusCode::SERVICE_UNAVAILABLE, "acceptor closed");
    }

    let mut response = response(
        StatusCode::OK,
        ServerBody::Stream(body),
        Some("application/octet-stream"),
    );
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        HeaderName::from_static("x-accel-buffering"),
        HeaderValue::from_static("no"),
    );
    response
}

fn response(
    status: StatusCode,
    body: ServerBody,
    content_type: Option<&'static str>,
) -> Response<ServerBody> {
    let mut builder = Response::builder().status(status);
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    builder.body(body).unwrap_or_else(|_| {
        let mut fallback = Response::new(ServerBody::Empty);
        *fallback.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        fallback
    })
}

fn text_response(status: StatusCode, text: &str) -> Response<ServerBody> {
    response(
        status,
        ServerBody::Full(Some(Bytes::from(text.to_owned()))),
        Some("text/plain; charset=utf-8"),
    )
}

fn health_response(health: &HealthFn) -> Response<ServerBody> {
    let body = health();
    let mut response = response(
        StatusCode::OK,
        ServerBody::Full(Some(Bytes::from(body))),
        Some("application/json"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Response body that is either streaming or fully known.
#[derive(Debug)]
enum ServerBody {
    Stream(MpscBody),
    Full(Option<Bytes>),
    Empty,
}

impl Body for ServerBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Stream(body) => Pin::new(body).poll_frame(cx),
            Self::Full(slot) => Poll::Ready(slot.take().map(|bytes| Ok(Frame::data(bytes)))),
            Self::Empty => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Stream(body) => body.is_end_stream(),
            Self::Full(slot) => slot.is_none(),
            Self::Empty => true,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Stream(body) => body.size_hint(),
            Self::Full(Some(bytes)) => SizeHint::with_exact(bytes.len() as u64),
            Self::Full(None) | Self::Empty => SizeHint::with_exact(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn loopback() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 0))
    }

    async fn read_head(socket: &mut TcpStream) -> std::io::Result<String> {
        let mut buf = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            socket.read_exact(&mut byte).await?;
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
            if buf.len() > 64 * 1024 {
                return Err(std::io::Error::other("head too large"));
            }
        }
        String::from_utf8(buf).map_err(|_| std::io::Error::other("non-utf8 head"))
    }

    async fn read_line(socket: &mut TcpStream) -> std::io::Result<String> {
        let mut buf = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            socket.read_exact(&mut byte).await?;
            buf.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
            if buf.len() > 8192 {
                return Err(std::io::Error::other("line too long"));
            }
        }
        String::from_utf8(buf).map_err(|_| std::io::Error::other("non-utf8 line"))
    }

    async fn read_http_chunk(socket: &mut TcpStream) -> std::io::Result<Vec<u8>> {
        let line = read_line(socket).await?;
        let text = line.trim_end_matches(['\r', '\n']);
        let size =
            usize::from_str_radix(text, 16).map_err(|_| std::io::Error::other("bad chunk size"))?;
        let mut data = vec![0_u8; size];
        socket.read_exact(&mut data).await?;
        let mut crlf = [0_u8; 2];
        socket.read_exact(&mut crlf).await?;
        Ok(data)
    }

    async fn read_all(socket: &mut TcpStream) -> std::io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        socket.read_to_end(&mut buf).await?;
        Ok(buf)
    }

    #[tokio::test]
    async fn u_http_loopback_keepalive() {
        let acceptor = match HttpAcceptor::bind(loopback(), "/team").await {
            Ok(acceptor) => acceptor,
            Err(error) => panic!("bind failed: {error}"),
        };
        let addr = match acceptor.local_addr() {
            Ok(addr) => addr,
            Err(error) => panic!("local_addr failed: {error}"),
        };
        let counter = acceptor.connection_counter();
        let endpoint = match Endpoint::parse(&format!("http://{addr}/team")) {
            Ok(endpoint) => endpoint,
            Err(error) => panic!("endpoint failed: {error}"),
        };

        let (chunk_tx, mut chunk_rx) = mpsc::channel::<Bytes>(8);
        let (nonce_tx, mut nonce_rx) = mpsc::channel::<u64>(4);
        let server = tokio::spawn(async move {
            let mut acceptor = acceptor;
            loop {
                match acceptor.accept_http().await {
                    Ok(AcceptedHttp::Rpc {
                        mut body,
                        end,
                        nonce,
                        ..
                    }) => {
                        let _ = nonce_tx.send(nonce).await;
                        while let Ok(Some(chunk)) = body.next_bytes().await {
                            if chunk_tx.send(chunk).await.is_err() {
                                break;
                            }
                        }
                        drop(end);
                    }
                    Ok(AcceptedHttp::Events { out, nonce, .. }) => {
                        let _ = nonce_tx.send(nonce).await;
                        let _ = out.send(Bytes::from_static(b"welcome")).await;
                    }
                    Err(_) => break,
                }
            }
        });

        let mut transport = match HttpTransport::dial(&endpoint, &DialOptions::new(11)).await {
            Ok(transport) => transport,
            Err(error) => panic!("dial failed: {error}"),
        };
        if let Err(error) = transport.send(Bytes::from_static(b"one")).await {
            panic!("first send failed: {error}");
        }
        if let Err(error) = transport.send(Bytes::from_static(b"two")).await {
            panic!("second send failed: {error}");
        }

        // Two chunks arrived through one POST body: keep-alive, one connection
        // for the uplink.
        match chunk_rx.recv().await {
            Some(chunk) => assert_eq!(chunk, Bytes::from_static(b"one")),
            None => panic!("uplink closed early"),
        }
        match chunk_rx.recv().await {
            Some(chunk) => assert_eq!(chunk, Bytes::from_static(b"two")),
            None => panic!("uplink closed early"),
        }
        match transport.recv().await {
            Ok(Some(chunk)) => assert_eq!(chunk, Bytes::from_static(b"welcome")),
            other => panic!("unexpected downlink: {other:?}"),
        }

        // Both halves carried the same X-SM-Nonce; pairing never needed an IP.
        assert_eq!(nonce_rx.recv().await, Some(11));
        assert_eq!(nonce_rx.recv().await, Some(11));

        // One connection for events, one for rpc. No per-chunk reconnect.
        assert_eq!(counter.load(Ordering::Relaxed), 2);
        if let Err(error) = transport.close().await {
            panic!("close failed: {error}");
        }
        server.abort();
    }

    #[tokio::test]
    async fn u_http_chunked_request_wire() {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => panic!("bind failed: {error}"),
        };
        let addr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(error) => panic!("local_addr failed: {error}"),
        };
        let endpoint = match Endpoint::parse(&format!("http://{addr}/team")) {
            Ok(endpoint) => endpoint,
            Err(error) => panic!("endpoint failed: {error}"),
        };

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            let head = read_head(&mut socket).await?;
            assert!(
                head.starts_with("POST /team/rpc HTTP/1.1\r\n"),
                "head: {head}"
            );
            let lower = head.to_ascii_lowercase();
            assert!(lower.contains("transfer-encoding: chunked"), "head: {head}");
            assert!(lower.contains("x-sm-nonce: 7"), "head: {head}");
            assert!(
                lower.contains("content-type: application/octet-stream"),
                "head: {head}"
            );
            let chunk = read_http_chunk(&mut socket).await?;
            assert_eq!(chunk, b"abc");
            socket
                .write_all(
                    b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await?;
            Ok::<(), std::io::Error>(())
        });

        let mut rpc = match HttpDialer
            .dial(&endpoint, StreamKind::Rpc, &DialOptions::new(7))
            .await
        {
            Ok(rpc) => rpc,
            Err(error) => panic!("dial failed: {error}"),
        };
        if let Err(error) = rpc.send(Bytes::from_static(b"abc")).await {
            panic!("send failed: {error}");
        }
        match rpc.recv().await {
            Ok(None) => {}
            other => panic!("unexpected rpc end: {other:?}"),
        }
        match server.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => panic!("server i/o failed: {error}"),
            Err(error) => panic!("server task failed: {error}"),
        }
    }

    #[tokio::test]
    async fn u_http_chunked_events_boundaries() {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => panic!("bind failed: {error}"),
        };
        let addr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(error) => panic!("local_addr failed: {error}"),
        };
        let endpoint = match Endpoint::parse(&format!("http://{addr}/team")) {
            Ok(endpoint) => endpoint,
            Err(error) => panic!("endpoint failed: {error}"),
        };

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            let head = read_head(&mut socket).await?;
            assert!(
                head.starts_with("GET /team/events HTTP/1.1\r\n"),
                "head: {head}"
            );
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\n\
                      cache-control: no-store\r\nx-accel-buffering: no\r\n\
                      transfer-encoding: chunked\r\n\r\n\
                      2\r\nAA\r\n3\r\nBBB\r\n0\r\n\r\n",
                )
                .await?;
            Ok::<(), std::io::Error>(())
        });

        let mut events = match HttpDialer
            .dial(&endpoint, StreamKind::Events, &DialOptions::new(8))
            .await
        {
            Ok(events) => events,
            Err(error) => panic!("dial failed: {error}"),
        };
        match events.recv().await {
            Ok(Some(chunk)) => assert_eq!(chunk, Bytes::from_static(b"AA")),
            other => panic!("unexpected first chunk: {other:?}"),
        }
        match events.recv().await {
            Ok(Some(chunk)) => assert_eq!(chunk, Bytes::from_static(b"BBB")),
            other => panic!("unexpected second chunk: {other:?}"),
        }
        match events.recv().await {
            Ok(None) => {}
            other => panic!("unexpected end: {other:?}"),
        }
        match server.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => panic!("server i/o failed: {error}"),
            Err(error) => panic!("server task failed: {error}"),
        }
    }

    #[tokio::test]
    async fn u_http_server_detects_client_disconnect() {
        let acceptor = match HttpAcceptor::bind(loopback(), "/s").await {
            Ok(acceptor) => acceptor,
            Err(error) => panic!("bind failed: {error}"),
        };
        let addr = match acceptor.local_addr() {
            Ok(addr) => addr,
            Err(error) => panic!("local_addr failed: {error}"),
        };
        let endpoint = match Endpoint::parse(&format!("http://{addr}/s")) {
            Ok(endpoint) => endpoint,
            Err(error) => panic!("endpoint failed: {error}"),
        };

        let (closed_tx, closed_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut acceptor = acceptor;
            loop {
                match acceptor.accept_http().await {
                    Ok(AcceptedHttp::Events { out, .. }) => {
                        let _ = out.send(Bytes::from_static(b"hello")).await;
                        out.closed().await;
                        let _ = closed_tx.send(());
                        break;
                    }
                    Ok(AcceptedHttp::Rpc { mut body, end, .. }) => {
                        while let Ok(Some(_chunk)) = body.next_bytes().await {}
                        drop(end);
                    }
                    Err(_) => break,
                }
            }
        });

        let mut transport = match HttpTransport::dial(&endpoint, &DialOptions::new(12)).await {
            Ok(transport) => transport,
            Err(error) => panic!("dial failed: {error}"),
        };
        match transport.recv().await {
            Ok(Some(chunk)) => assert_eq!(chunk, Bytes::from_static(b"hello")),
            other => panic!("unexpected chunk: {other:?}"),
        }
        drop(transport);
        match tokio::time::timeout(Duration::from_secs(5), closed_rx).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => panic!("server signal dropped: {error}"),
            Err(_) => panic!("server did not observe the disconnect"),
        }
        server.abort();
    }

    #[tokio::test]
    async fn u_http_client_detects_server_close() {
        let acceptor = match HttpAcceptor::bind(loopback(), "/s").await {
            Ok(acceptor) => acceptor,
            Err(error) => panic!("bind failed: {error}"),
        };
        let addr = match acceptor.local_addr() {
            Ok(addr) => addr,
            Err(error) => panic!("local_addr failed: {error}"),
        };
        let endpoint = match Endpoint::parse(&format!("http://{addr}/s")) {
            Ok(endpoint) => endpoint,
            Err(error) => panic!("endpoint failed: {error}"),
        };

        let server = tokio::spawn(async move {
            let mut acceptor = acceptor;
            loop {
                match acceptor.accept_http().await {
                    Ok(AcceptedHttp::Events { out, .. }) => {
                        let _ = out.send(Bytes::from_static(b"bye")).await;
                        // Dropping `out` ends the response body.
                    }
                    Ok(AcceptedHttp::Rpc { mut body, end, .. }) => {
                        while let Ok(Some(_chunk)) = body.next_bytes().await {}
                        drop(end);
                    }
                    Err(_) => break,
                }
            }
        });

        let mut transport = match HttpTransport::dial(&endpoint, &DialOptions::new(13)).await {
            Ok(transport) => transport,
            Err(error) => panic!("dial failed: {error}"),
        };
        match transport.recv().await {
            Ok(Some(chunk)) => assert_eq!(chunk, Bytes::from_static(b"bye")),
            other => panic!("unexpected chunk: {other:?}"),
        }
        match transport.recv().await {
            Ok(None) => {}
            other => panic!("unexpected end: {other:?}"),
        }
        match transport.send(Bytes::from_static(b"after-close")).await {
            Err(TransportError::Disconnected) => {}
            other => panic!("unexpected send result: {other:?}"),
        }
        server.abort();
    }

    #[tokio::test]
    async fn u_http_events_headers_healthz_and_prefix() {
        let acceptor = match HttpAcceptor::bind(loopback(), "/sync").await {
            Ok(acceptor) => acceptor,
            Err(error) => panic!("bind failed: {error}"),
        };
        let addr = match acceptor.local_addr() {
            Ok(addr) => addr,
            Err(error) => panic!("local_addr failed: {error}"),
        };
        let server = tokio::spawn(async move {
            let mut acceptor = acceptor;
            loop {
                if acceptor.accept_http().await.is_err() {
                    break;
                }
            }
        });

        // healthz is prefix-free and needs no nonce.
        let mut socket = match TcpStream::connect(addr).await {
            Ok(socket) => socket,
            Err(error) => panic!("connect failed: {error}"),
        };
        if let Err(error) = socket
            .write_all(
                b"GET /__syncmount/healthz HTTP/1.1\r\nhost: test\r\nconnection: close\r\n\r\n",
            )
            .await
        {
            panic!("write failed: {error}");
        }
        let text = match read_all(&mut socket).await {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(error) => panic!("read failed: {error}"),
        };
        assert!(text.starts_with("HTTP/1.1 200"), "response: {text}");
        let lower = text.to_ascii_lowercase();
        assert!(
            lower.contains("content-type: application/json"),
            "response: {text}"
        );
        assert!(text.contains("\"status\":\"ok\""), "response: {text}");

        // The downlink advertises streaming to reverse proxies.
        let mut socket = match TcpStream::connect(addr).await {
            Ok(socket) => socket,
            Err(error) => panic!("connect failed: {error}"),
        };
        if let Err(error) = socket
            .write_all(b"GET /sync/events HTTP/1.1\r\nhost: test\r\nx-sm-nonce: 5\r\n\r\n")
            .await
        {
            panic!("write failed: {error}");
        }
        let head = match read_head(&mut socket).await {
            Ok(head) => head,
            Err(error) => panic!("read failed: {error}"),
        };
        assert!(head.starts_with("HTTP/1.1 200"), "head: {head}");
        let lower = head.to_ascii_lowercase();
        assert!(lower.contains("x-accel-buffering: no"), "head: {head}");
        assert!(lower.contains("cache-control: no-store"), "head: {head}");
        assert!(lower.contains("transfer-encoding: chunked"), "head: {head}");
        assert!(
            lower.contains("content-type: application/octet-stream"),
            "head: {head}"
        );

        // Prefix matching is exact: /sync2 is not /sync.
        let mut socket = match TcpStream::connect(addr).await {
            Ok(socket) => socket,
            Err(error) => panic!("connect failed: {error}"),
        };
        if let Err(error) = socket
            .write_all(
                b"POST /sync2/rpc HTTP/1.1\r\nhost: test\r\nx-sm-nonce: 1\r\n\
                  transfer-encoding: chunked\r\nconnection: close\r\n\r\n0\r\n\r\n",
            )
            .await
        {
            panic!("write failed: {error}");
        }
        let text = match read_all(&mut socket).await {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(error) => panic!("read failed: {error}"),
        };
        assert!(text.starts_with("HTTP/1.1 404"), "response: {text}");

        // A missing pairing header is a client error, not a session.
        let mut socket = match TcpStream::connect(addr).await {
            Ok(socket) => socket,
            Err(error) => panic!("connect failed: {error}"),
        };
        if let Err(error) = socket
            .write_all(
                b"POST /sync/rpc HTTP/1.1\r\nhost: test\r\ncontent-length: 0\r\n\
                  connection: close\r\n\r\n",
            )
            .await
        {
            panic!("write failed: {error}");
        }
        let text = match read_all(&mut socket).await {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(error) => panic!("read failed: {error}"),
        };
        assert!(text.starts_with("HTTP/1.1 400"), "response: {text}");
        server.abort();
    }

    #[tokio::test]
    async fn u_http_tls_is_refused() {
        let endpoint = match Endpoint::parse("https://127.0.0.1:1/sync") {
            Ok(endpoint) => endpoint,
            Err(error) => panic!("endpoint failed: {error}"),
        };
        match HttpDialer
            .dial(&endpoint, StreamKind::Rpc, &DialOptions::new(1))
            .await
        {
            Err(TransportError::TlsUnsupported) => {}
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("TLS dial unexpectedly succeeded"),
        }
    }

    #[tokio::test]
    async fn u_http_wrong_direction_is_rejected() {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => panic!("bind failed: {error}"),
        };
        let addr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(error) => panic!("local_addr failed: {error}"),
        };
        let endpoint = match Endpoint::parse(&format!("http://{addr}/team")) {
            Ok(endpoint) => endpoint,
            Err(error) => panic!("endpoint failed: {error}"),
        };
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            let _head = read_head(&mut socket).await?;
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\n\
                      transfer-encoding: chunked\r\n\r\n0\r\n\r\n",
                )
                .await?;
            Ok::<(), std::io::Error>(())
        });
        let mut events = match HttpDialer
            .dial(&endpoint, StreamKind::Events, &DialOptions::new(3))
            .await
        {
            Ok(events) => events,
            Err(error) => panic!("dial failed: {error}"),
        };
        match events.send(Bytes::from_static(b"nope")).await {
            Err(TransportError::WrongDirection(StreamKind::Events, _)) => {}
            other => panic!("unexpected send result: {other:?}"),
        }
        server.abort();
    }

    #[tokio::test]
    async fn u_http_keepalive_options_on_both_ends() {
        let listener = match TcpListener::bind(loopback()).await {
            Ok(listener) => listener,
            Err(error) => panic!("bind failed: {error}"),
        };
        let addr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(error) => panic!("local_addr failed: {error}"),
        };
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            configure_keepalive(&stream)?;
            Ok::<TcpStream, TransportError>(stream)
        });

        let client = match TcpStream::connect(addr).await {
            Ok(stream) => stream,
            Err(error) => panic!("connect failed: {error}"),
        };
        if let Err(error) = configure_keepalive(&client) {
            panic!("client keepalive failed: {error}");
        }
        let server = match server.await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => panic!("server keepalive failed: {error}"),
            Err(error) => panic!("server task failed: {error}"),
        };

        for stream in [&client, &server] {
            assert_eq!(
                rustix::net::sockopt::socket_keepalive(stream),
                Ok(true),
                "keepalive not enabled"
            );
            assert_eq!(
                rustix::net::sockopt::tcp_keepidle(stream),
                Ok(KEEPALIVE_TIME),
                "keepidle mismatch"
            );
            assert_eq!(
                rustix::net::sockopt::tcp_keepintvl(stream),
                Ok(KEEPALIVE_INTERVAL),
                "keepintvl mismatch"
            );
            assert_eq!(
                rustix::net::sockopt::tcp_keepcnt(stream),
                Ok(KEEPALIVE_RETRIES),
                "keepcnt mismatch"
            );
        }
    }
}
