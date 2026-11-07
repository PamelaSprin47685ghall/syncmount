//! Transport: HTTP/1.1 dual streams, streaming bodies, endpoint derivation.
//!
//! This layer moves **bytes only**. It never parses a frame, never encrypts,
//! never validates a signature, and never decides what an operation means.
//! Frame boundaries are owned by [`crate::protocol::codec`]; HTTP chunk
//! boundaries carry no protocol meaning (51 §3.3).
//!
//! # Shape
//!
//! A logical session is two independent HTTP/1.1 requests (24 §1):
//!
//! ```text
//! uplink    POST {prefix}/rpc      request body,  chunked, long-lived
//! downlink  GET  {prefix}/events   response body, chunked, long-lived
//! ```
//!
//! The two requests may arrive in any order, from any source port. They are
//! paired by the `X-SM-Nonce` header, never by IP address
//! ([`endpoint::PairingTable`]). `X-SM-Client-Id` is a declaration, not a
//! credential.
//!
//! # Ports
//!
//! [`Transport`], [`Dialer`] and [`Acceptor`] are byte-level ports. The
//! testkit substitutes an in-memory implementation; [`http1`] provides the
//! production implementation over hyper. No `Frame` type appears here: the
//! port carries `Bytes`, so the dependency direction stays
//! `client/server → transport` and never the reverse.

pub mod body;
pub mod endpoint;
pub mod http1;

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use bytes::Bytes;

pub use body::{BodyError, BodyStream, MpscBody, MpscSender};
pub use endpoint::{
    CLIENT_ID_HEADER, EVENTS_SUFFIX, Endpoint, EndpointError, HEALTHZ_PATH, NONCE_HEADER,
    PAIR_TIMEOUT, PairingError, PairingTable, RPC_SUFFIX, Scheme, client_id_from_headers,
    client_id_header, nonce_from_headers, nonce_header, normalize_prefix,
};
pub use http1::{AcceptedHttp, EventsStream, HttpAcceptor, HttpDialer, HttpTransport, RpcStream};

/// Queue depth, in chunks, for each direction of a body.
///
/// A chunk is at most one frame (64 KiB plaintext plus envelope), so the
/// default bounds one direction at roughly 4 MiB. Capacity is the only buffer
/// in the path: a producer that outruns the socket waits (42 §3.4 L2).
pub const BODY_QUEUE_DEPTH: usize = 64;

/// Boxed future used by the transport ports.
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Which half of a session a stream carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StreamKind {
    /// `POST {prefix}/rpc`, client → server frames.
    Rpc,
    /// `GET {prefix}/events`, server → client frames.
    Events,
}

impl StreamKind {
    /// Path suffix appended to the endpoint namespace.
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Rpc => RPC_SUFFIX,
            Self::Events => EVENTS_SUFFIX,
        }
    }
}

impl fmt::Display for StreamKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Rpc => "rpc",
            Self::Events => "events",
        })
    }
}

/// Opaque peer handle for diagnostics.
///
/// It is a connection serial, not an address and not an identity. Pairing
/// never uses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerId(pub [u8; 16]);

impl PeerId {
    /// Derive a peer handle from a monotonic connection serial.
    pub fn from_serial(serial: u64) -> Self {
        let mut bytes = [0_u8; 16];
        bytes[8..].copy_from_slice(&serial.to_be_bytes());
        Self(bytes)
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

/// Per-dial parameters shared by both streams of one session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DialOptions {
    /// Random `u64` that pairs the two streams.
    pub nonce: u64,
    /// Client id declaration, if this is a reconnect.
    pub client_id: Option<[u8; 16]>,
}

impl DialOptions {
    /// Options with no client-id declaration.
    pub const fn new(nonce: u64) -> Self {
        Self {
            nonce,
            client_id: None,
        }
    }

    /// Fresh pairing token from the process entropy source.
    ///
    /// The nonce is a rendezvous token, not a credential; 64 random bits are
    /// enough to make a cross-session collision negligible.
    pub fn random() -> Self {
        Self::new(rand::random::<u64>())
    }

    /// Add a client-id declaration.
    pub const fn with_client_id(mut self, client_id: [u8; 16]) -> Self {
        self.client_id = Some(client_id);
        self
    }
}

/// One byte-level stream of a session.
///
/// `Rpc` streams send; `Events` streams receive. The opposite direction
/// returns [`TransportError::WrongDirection`] instead of silently dropping
/// bytes.
pub trait Transport: Send {
    /// Append bytes to the stream.
    fn send(&mut self, chunk: Bytes) -> BoxFut<'_, Result<(), TransportError>>;

    /// Read the next chunk, or `None` at a clean end of stream.
    fn recv(&mut self) -> BoxFut<'_, Result<Option<Bytes>, TransportError>>;

    /// Close the stream. Idempotent.
    fn close(&mut self) -> BoxFut<'_, Result<(), TransportError>>;
}

/// Create one stream of a session.
pub trait Dialer: Send + Sync {
    /// Dial `kind` for `endpoint`. Both calls of one session must carry the
    /// same [`DialOptions::nonce`].
    fn dial<'a>(
        &'a self,
        endpoint: &'a Endpoint,
        kind: StreamKind,
        options: &'a DialOptions,
    ) -> BoxFut<'a, Result<Box<dyn Transport>, TransportError>>;
}

/// Accept one stream of a session.
pub trait Acceptor: Send + Sync {
    /// Wait for the next accepted stream.
    fn accept(&self) -> BoxFut<'_, Result<AcceptedConn, TransportError>>;
}

/// One accepted stream, before any frame is interpreted.
pub struct AcceptedConn {
    /// Diagnostic peer handle.
    pub peer: PeerId,
    /// Which half of the session this stream carries.
    pub kind: StreamKind,
    /// Pairing token from `X-SM-Nonce`.
    pub nonce: u64,
    /// Client id declaration, if present.
    pub client_id: Option<[u8; 16]>,
    /// Byte stream.
    pub transport: Box<dyn Transport>,
}

impl fmt::Debug for AcceptedConn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcceptedConn")
            .field("peer", &self.peer)
            .field("kind", &self.kind)
            .field("nonce", &self.nonce)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// Transport failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// Socket failure.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// HTTP/1.1 connection failure.
    #[error("hyper error: {0}")]
    Hyper(#[from] hyper::Error),
    /// Request construction failure.
    #[error("invalid HTTP request: {0}")]
    Http(String),
    /// Peer answered with an unexpected status.
    #[error("unexpected HTTP status {0}")]
    Status(http::StatusCode),
    /// The connection ended or was closed locally.
    #[error("connection closed")]
    Disconnected,
    /// A stream was used in the direction it does not carry.
    #[error("stream {0} cannot {1}")]
    WrongDirection(StreamKind, &'static str),
    /// Streaming body failure.
    #[error("body error: {0}")]
    Body(#[from] BodyError),
    /// Endpoint or header failure.
    #[error("endpoint error: {0}")]
    Endpoint(#[from] EndpointError),
    /// TLS is not implemented in v1.
    #[error("TLS is not implemented; dial an http:// endpoint")]
    TlsUnsupported,
    /// The acceptor was dropped.
    #[error("acceptor closed")]
    Closed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u_transport_stream_suffixes() {
        assert_eq!(StreamKind::Rpc.suffix(), "/rpc");
        assert_eq!(StreamKind::Events.suffix(), "/events");
        assert_eq!(StreamKind::Rpc.to_string(), "rpc");
    }

    #[test]
    fn u_transport_peer_id_is_diagnostic_only() {
        let peer = PeerId::from_serial(0x0102);
        assert_eq!(&peer.0[8..], &[0, 0, 0, 0, 0, 0, 1, 2]);
        assert_eq!(peer.0[..8], [0; 8]);
    }

    #[test]
    fn u_transport_dial_options_carry_client_id() {
        let options = DialOptions::new(9).with_client_id([1; 16]);
        assert_eq!(options.nonce, 9);
        assert_eq!(options.client_id, Some([1; 16]));
    }
}
