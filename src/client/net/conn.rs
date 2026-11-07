//! Dual-stream connection and the HELLO/WELCOME handshake.
//!
//! Owner: W12 (E5). See 41 §2.8, 44 §2, 51 §3.2 and 53 W12.
//!
//! [`Conn`] dials both HTTP streams through W8's [`HttpTransport`]. The
//! streams are paired by `X-SM-Nonce` inside the transport, never by address.
//! After the handshake the connection is split into an [`Uplink`] and the
//! downlink task's byte stream; the split makes ownership explicit and keeps
//! two writers from racing on one HTTP connection.
//!
//! The handshake is deliberately narrow:
//!
//! ```text
//! client                                server
//!   |  HELLO (plain WCP, ctrl prefix)     |
//!   |----------------------------------->|
//!   |  WELCOME (plain WCP)                |
//!   |<-----------------------------------|
//! ```
//!
//! `HELLO` is plaintext because the server must read `client_id`, version and
//! capabilities before it can bind a session (44 D3). `WELCOME` is plaintext
//! because the server holds no keys. The `client_id` echoed by `WELCOME` must
//! equal the one in `HELLO`; a mismatch is a protocol failure, not a hint.

use std::time::Duration;

use bytes::Bytes;

use crate::protocol::{
    CtrlPrefix, FrameBuf, FrameDecoder, FrameEncoder, FrameRef, Hello, Limits, Message, MsgType,
    Negotiated, Prefix, Seq, Welcome, decode_plain, negotiate,
};
use crate::transport::{
    DialOptions, Endpoint, HttpTransport, RpcStream, Transport, TransportError,
};

use super::encode_control;

/// Default handshake deadline. A server that accepts TCP and then says
/// nothing must not pin the process in MOUNTING.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a connection could not be established or handshaken.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConnError {
    /// The byte transport failed.
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    /// A frame boundary or flag was invalid.
    #[error("frame: {0}")]
    Protocol(#[from] crate::protocol::ProtocolError),
    /// A plaintext message body was invalid.
    #[error("message: {0}")]
    Message(#[from] crate::protocol::MessageError),
    /// Protocol version or capability negotiation failed.
    #[error("version: {0}")]
    Version(#[from] crate::protocol::VersionError),
    /// The server answered with `ERROR`.
    #[error("server error: {reason:?}")]
    Server {
        /// Transport reason.
        reason: crate::protocol::TrnReason,
        /// Diagnostic bytes, never user paths.
        detail: Vec<u8>,
    },
    /// The server answered with `KICK`.
    #[error("kicked: {0:?}")]
    Kicked(crate::protocol::KickReason),
    /// The server sent a message that is not legal before `WELCOME`.
    #[error("unexpected message {0:?} during handshake")]
    Unexpected(MsgType),
    /// `WELCOME` echoed a different `client_id`.
    #[error("WELCOME client_id does not match HELLO")]
    ClientIdMismatch,
    /// The stream ended before `WELCOME`.
    #[error("connection closed during handshake")]
    Closed,
    /// The handshake did not finish before the deadline.
    #[error("handshake timed out after {0:?}")]
    Timeout(Duration),
    /// `into_parts` was called before `hello`.
    #[error("connection was not handshaken")]
    NotHandshaken,
}

/// One dialled session before the handshake.
#[derive(Debug)]
pub struct Conn {
    transport: HttpTransport,
    decoder: FrameDecoder,
    limits: Limits,
    timeout: Duration,
    welcome: Option<Welcome>,
    negotiated: Option<Negotiated>,
}

impl Conn {
    /// Dial both streams and prepare the handshake decoder.
    pub async fn dial(
        endpoint: &Endpoint,
        options: DialOptions,
        limits: Limits,
    ) -> Result<Self, ConnError> {
        let transport = HttpTransport::dial(endpoint, &options).await?;
        Ok(Self {
            transport,
            decoder: FrameDecoder::new(limits),
            limits,
            timeout: HANDSHAKE_TIMEOUT,
            welcome: None,
            negotiated: None,
        })
    }

    /// Replace the handshake deadline.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Current limits.
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// The accepted `WELCOME`, once the handshake finished.
    pub const fn welcome(&self) -> Option<Welcome> {
        self.welcome
    }

    /// The negotiated version and capability intersection.
    pub const fn negotiated(&self) -> Option<Negotiated> {
        self.negotiated
    }

    /// Send `HELLO` and wait for `WELCOME`.
    ///
    /// `applied` and `epoch_seen` are the watermark carried in the ctrl
    /// prefix; a fresh process sends `Seq::UNSEQUENCED` and `0`, a reconnect
    /// sends its last applied values (39 §2.2).
    pub async fn hello(
        &mut self,
        hello: Hello,
        applied: Seq,
        epoch_seen: u64,
    ) -> Result<Welcome, ConnError> {
        let timeout = self.timeout;
        match tokio::time::timeout(timeout, self.hello_inner(hello, applied, epoch_seen)).await {
            Ok(result) => result,
            Err(_) => Err(ConnError::Timeout(timeout)),
        }
    }

    async fn hello_inner(
        &mut self,
        hello: Hello,
        applied: Seq,
        epoch_seen: u64,
    ) -> Result<Welcome, ConnError> {
        let body = Message::Hello(hello).encode_plain()?;
        let prefix = Prefix::Ctrl(CtrlPrefix::new(applied, epoch_seen));
        let frame = encode_control(MsgType::HELLO, prefix, &body, Seq::UNSEQUENCED)?;
        self.transport.send(Bytes::from(frame)).await?;

        loop {
            let frame = self.next_frame().await?.ok_or(ConnError::Closed)?;
            match frame.header.msg_type {
                MsgType::WELCOME => {
                    let Message::Welcome(welcome) =
                        decode_plain(MsgType::WELCOME, &frame.body, &self.limits)?
                    else {
                        return Err(ConnError::Unexpected(frame.header.msg_type));
                    };
                    if welcome.client_id != hello.client_id {
                        return Err(ConnError::ClientIdMismatch);
                    }
                    let negotiated =
                        negotiate(hello.proto, welcome.proto, hello.caps, welcome.caps)?;
                    self.welcome = Some(welcome);
                    self.negotiated = Some(negotiated);
                    return Ok(welcome);
                }
                MsgType::ERROR => {
                    let Message::Error(error) =
                        decode_plain(MsgType::ERROR, &frame.body, &self.limits)?
                    else {
                        return Err(ConnError::Unexpected(frame.header.msg_type));
                    };
                    return Err(ConnError::Server {
                        reason: error.reason,
                        detail: error.detail.to_vec(),
                    });
                }
                MsgType::KICK => {
                    let Message::Kick(kick) =
                        decode_plain(MsgType::KICK, &frame.body, &self.limits)?
                    else {
                        return Err(ConnError::Unexpected(frame.header.msg_type));
                    };
                    return Err(ConnError::Kicked(kick.reason));
                }
                // A server may answer an early PING before WELCOME; it is not
                // an error, but the handshake does not act on it.
                MsgType::PONG => continue,
                other => return Err(ConnError::Unexpected(other)),
            }
        }
    }

    async fn next_frame(&mut self) -> Result<Option<FrameBuf>, ConnError> {
        loop {
            if let Some(frame) = self.decoder.next_frame_owned()? {
                return Ok(Some(frame));
            }
            match self.transport.recv().await? {
                Some(chunk) => self.decoder.push(&chunk)?,
                None => {
                    self.decoder.finish()?;
                    return Ok(None);
                }
            }
        }
    }

    /// Split the handshaken session into its two owners.
    ///
    /// The decoder is handed to the downlink with any bytes it already
    /// buffered after `WELCOME`, so no frame can be lost at the split.
    pub fn into_parts(self) -> Result<ConnParts, ConnError> {
        let welcome = self.welcome.ok_or(ConnError::NotHandshaken)?;
        let (rpc, events) = self.transport.split();
        Ok(ConnParts {
            events,
            decoder: self.decoder,
            welcome,
            uplink: Uplink::new(rpc),
        })
    }
}

/// The two independently owned halves of a handshaken session.
#[derive(Debug)]
pub struct ConnParts {
    /// Downlink byte stream.
    pub events: crate::transport::EventsStream,
    /// Frame decoder carrying any post-WELCOME residue.
    pub decoder: FrameDecoder,
    /// Accepted `WELCOME`.
    pub welcome: Welcome,
    /// Uplink writer.
    pub uplink: Uplink,
}

/// Client-to-server frame writer.
///
/// It owns the only handle to the RPC stream, so two tasks cannot interleave
/// half-frames. `send` checks the frame and writes one HTTP chunk; the
/// transport's bounded body supplies the backpressure.
#[derive(Debug)]
pub struct Uplink {
    rpc: RpcStream,
    encoder: FrameEncoder,
}

impl Uplink {
    /// Wrap an RPC stream.
    pub fn new(rpc: RpcStream) -> Self {
        Self {
            rpc,
            encoder: FrameEncoder::new(),
        }
    }

    /// Encode and send one frame.
    pub async fn send(&mut self, frame: &FrameBuf) -> Result<(), UplinkError> {
        let bytes =
            self.encoder
                .encode_owned(&FrameRef::new(&frame.header, &frame.prefix, &frame.body))?;
        self.rpc.send(Bytes::from(bytes)).await?;
        Ok(())
    }

    /// Send bytes that are already a complete frame.
    pub async fn send_bytes(&mut self, bytes: Bytes) -> Result<(), UplinkError> {
        self.rpc.send(bytes).await?;
        Ok(())
    }

    /// Close the uplink. Idempotent.
    pub async fn close(mut self) -> Result<(), UplinkError> {
        self.rpc.close().await?;
        Ok(())
    }
}

/// Uplink failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UplinkError {
    /// Frame encoding failed.
    #[error("frame: {0}")]
    Protocol(#[from] crate::protocol::ProtocolError),
    /// The transport failed.
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    /// AEAD sealing failed.
    #[error("crypto: {0}")]
    Crypto(#[from] crate::protocol::crypto::CryptoError),
    /// Stream fragmentation failed.
    #[error("fragment: {0}")]
    Fragment(#[from] crate::protocol::FragmentError),
    /// A WCP body was invalid.
    #[error("message: {0}")]
    Message(#[from] crate::protocol::MessageError),
    /// WCP encoding failed.
    #[error("wcp: {0}")]
    Wcp(#[from] crate::protocol::WcpError),
    /// The local backing refused a path or attribute lookup.
    #[error("store: {0}")]
    Store(#[from] crate::store::Errno),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::net::SocketAddr;

    use tokio::sync::oneshot;

    use super::*;
    use crate::client::net::encode_control;
    use crate::protocol::{
        Caps, ClientId, JoinState, KickReason, Message, ProtoVersion, ResyncMode, TrnReason,
        WelcomeLimits,
    };
    use crate::transport::{AcceptedHttp, BodyStream, HttpAcceptor, MpscSender};

    const CLIENT: [u8; 16] = [0x11; 16];

    fn welcome(client_id: ClientId) -> Welcome {
        Welcome {
            proto: ProtoVersion::CURRENT,
            caps: Caps::REQUIRED,
            epoch: 9,
            current_seq: Seq(41),
            client_id,
            resync: ResyncMode::ManifestDiff,
            limits: WelcomeLimits {
                max_frame: 128 * 1024,
                credit_bytes: 1 << 20,
                session_ttl_s: 60,
                max_sessions: 8,
            },
            server_time: 1_700_000_000,
            server_nonce: [0x22; 32],
            join_state: JoinState::Accepted,
            session_id: None,
            snapshot_ref: None,
            view_holder: None,
            view_seq: None,
            view_session: None,
            view_self: false,
            view_bootstrap: false,
        }
    }

    fn control(msg_type: MsgType, body: &[u8], seq: Seq) -> Bytes {
        Bytes::from(
            encode_control(msg_type, Prefix::None, body, seq)
                .unwrap_or_else(|err| panic!("encode control: {err}")),
        )
    }

    async fn read_frame(body: &mut BodyStream<hyper::body::Incoming>) -> FrameBuf {
        let mut decoder = FrameDecoder::new(Limits::default());
        loop {
            if let Some(frame) = decoder
                .next_frame_owned()
                .unwrap_or_else(|err| panic!("decode: {err}"))
            {
                return frame;
            }
            let chunk = body
                .next_bytes()
                .await
                .unwrap_or_else(|err| panic!("body: {err}"))
                .unwrap_or_else(|| panic!("body ended before HELLO"));
            decoder
                .push(&chunk)
                .unwrap_or_else(|err| panic!("push: {err}"));
        }
    }

    struct Accepted {
        events: Option<(u64, MpscSender)>,
        rpc: Option<(u64, Option<[u8; 16]>, BodyStream<hyper::body::Incoming>)>,
    }

    async fn accept_both(acceptor: &mut HttpAcceptor) -> Accepted {
        let mut accepted = Accepted {
            events: None,
            rpc: None,
        };
        while accepted.events.is_none() || accepted.rpc.is_none() {
            match acceptor
                .accept_http()
                .await
                .unwrap_or_else(|err| panic!("accept: {err}"))
            {
                AcceptedHttp::Events { nonce, out, .. } => {
                    accepted.events = Some((nonce, out));
                }
                AcceptedHttp::Rpc {
                    nonce,
                    client_id,
                    body,
                    ..
                } => {
                    accepted.rpc = Some((nonce, client_id, body));
                }
            }
        }
        accepted
    }

    async fn loopback() -> (Endpoint, HttpAcceptor) {
        let acceptor = HttpAcceptor::bind(
            "127.0.0.1:0"
                .parse::<SocketAddr>()
                .unwrap_or_else(|err| panic!("addr: {err}")),
            "/sync",
        )
        .await
        .unwrap_or_else(|err| panic!("bind: {err}"));
        let addr = acceptor
            .local_addr()
            .unwrap_or_else(|err| panic!("local addr: {err}"));
        let endpoint = Endpoint::parse(&format!("http://{addr}/sync"))
            .unwrap_or_else(|err| panic!("endpoint: {err}"));
        (endpoint, acceptor)
    }

    /// 45 F6/F7 / 51 C2: HELLO and WELCOME cross the real W8 transport, and
    /// both streams carry the same `X-SM-Nonce`.
    #[tokio::test]
    async fn i_conn_hello_welcome_loopback() {
        let (endpoint, mut acceptor) = loopback().await;
        let (stop_tx, stop_rx) = oneshot::channel();
        let (pair_tx, pair_rx) = oneshot::channel();

        let server = tokio::spawn(async move {
            let accepted = accept_both(&mut acceptor).await;
            let (events_nonce, out) = accepted.events.expect("events half");
            let (rpc_nonce, declared, mut body) = accepted.rpc.expect("rpc half");
            pair_tx
                .send((events_nonce, rpc_nonce, declared))
                .expect("pair report");

            let frame = read_frame(&mut body).await;
            assert_eq!(frame.header.msg_type, MsgType::HELLO);
            assert_eq!(frame.header.seq, Seq::UNSEQUENCED);
            let ctrl = frame.prefix.as_ctrl().expect("ctrl prefix");
            assert_eq!(ctrl.applied_seq, Seq(3));
            assert_eq!(ctrl.epoch_seen, 7);
            let Message::Hello(hello) =
                decode_plain(MsgType::HELLO, &frame.body, &Limits::default()).expect("hello")
            else {
                panic!("expected HELLO");
            };
            assert_eq!(hello.client_id, ClientId::from_bytes(CLIENT));

            let body = welcome(hello.client_id).encode().expect("welcome body");
            out.send(control(MsgType::WELCOME, &body, Seq::UNSEQUENCED))
                .await
                .expect("send welcome");
            let _ = stop_rx.await;
        });

        let options = DialOptions::new(0xdead_beef).with_client_id(CLIENT);
        let mut conn = Conn::dial(&endpoint, options, Limits::default())
            .await
            .unwrap_or_else(|err| panic!("dial: {err}"));
        let hello = Hello::new(
            ProtoVersion::CURRENT,
            Caps::REQUIRED,
            ClientId::from_bytes(CLIENT),
            [0x33; 32],
        );
        let accepted = conn
            .hello(hello, Seq(3), 7)
            .await
            .unwrap_or_else(|err| panic!("hello: {err}"));
        assert_eq!(accepted.epoch, 9);
        assert_eq!(accepted.current_seq, Seq(41));
        assert_eq!(
            conn.negotiated().map(|n| n.proto),
            Some(ProtoVersion::CURRENT)
        );

        let (events_nonce, rpc_nonce, declared) = pair_rx.await.expect("pair report");
        assert_eq!(events_nonce, 0xdead_beef);
        assert_eq!(rpc_nonce, 0xdead_beef);
        assert_eq!(declared, Some(CLIENT));

        let _ = stop_tx.send(());
        server.await.expect("server task");
    }

    /// 45 F8 / INV-14: a KICK ends the handshake with the server's reason.
    #[tokio::test]
    async fn i_conn_handshake_kick() {
        let (endpoint, mut acceptor) = loopback().await;
        let (stop_tx, stop_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let accepted = accept_both(&mut acceptor).await;
            let (_, out) = accepted.events.expect("events half");
            let (_, _, mut body) = accepted.rpc.expect("rpc half");
            let _ = read_frame(&mut body).await;
            let body = crate::protocol::Kick {
                reason: KickReason::DuplicateClient,
            }
            .encode()
            .expect("kick body");
            out.send(control(MsgType::KICK, &body, Seq(11)))
                .await
                .expect("send kick");
            let _ = stop_rx.await;
        });

        let mut conn = Conn::dial(
            &endpoint,
            DialOptions::new(1).with_client_id(CLIENT),
            Limits::default(),
        )
        .await
        .unwrap_or_else(|err| panic!("dial: {err}"));
        let hello = Hello::new(
            ProtoVersion::CURRENT,
            Caps::REQUIRED,
            ClientId::from_bytes(CLIENT),
            [0x44; 32],
        );
        let error = conn
            .hello(hello, Seq::UNSEQUENCED, 0)
            .await
            .expect_err("KICK must fail the handshake");
        assert!(matches!(
            error,
            ConnError::Kicked(KickReason::DuplicateClient)
        ));
        let _ = stop_tx.send(());
        server.await.expect("server task");
    }

    /// 44 §4.5: an ERROR before WELCOME is a handshake failure, not a hint.
    #[tokio::test]
    async fn i_conn_handshake_server_error() {
        let (endpoint, mut acceptor) = loopback().await;
        let (stop_tx, stop_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let accepted = accept_both(&mut acceptor).await;
            let (_, out) = accepted.events.expect("events half");
            let (_, _, mut body) = accepted.rpc.expect("rpc half");
            let _ = read_frame(&mut body).await;
            let body = crate::protocol::ErrorMessage {
                reason: TrnReason::Version,
                detail: b"major mismatch",
                session_id: None,
            }
            .encode()
            .expect("error body");
            out.send(control(MsgType::ERROR, &body, Seq::UNSEQUENCED))
                .await
                .expect("send error");
            let _ = stop_rx.await;
        });

        let mut conn = Conn::dial(
            &endpoint,
            DialOptions::new(2).with_client_id(CLIENT),
            Limits::default(),
        )
        .await
        .unwrap_or_else(|err| panic!("dial: {err}"));
        let hello = Hello::new(
            ProtoVersion::CURRENT,
            Caps::REQUIRED,
            ClientId::from_bytes(CLIENT),
            [0x55; 32],
        );
        let error = conn
            .hello(hello, Seq::UNSEQUENCED, 0)
            .await
            .expect_err("ERROR must fail the handshake");
        match error {
            ConnError::Server { reason, detail } => {
                assert_eq!(reason, TrnReason::Version);
                assert_eq!(detail, b"major mismatch");
            }
            other => panic!("unexpected error: {other:?}"),
        }
        let _ = stop_tx.send(());
        server.await.expect("server task");
    }
}
