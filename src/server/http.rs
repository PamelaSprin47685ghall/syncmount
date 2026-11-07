//! HTTP surface and process lifecycle.
//!
//! [`Server::bind`] assembles the actor, the acceptor and the ticker.
//! [`Server::run_with_shutdown`] owns the accept loop; `healthz` is served by
//! the acceptor's synchronous closure, so a probe never waits on the actor
//! (42 §7.4).
//!
//! Routing itself lives in [`crate::transport::http1::HttpAcceptor`]: exactly
//! `{prefix}/rpc`, `{prefix}/events` and the absolute `/__syncmount/healthz`.
//! This module only maps accepted requests to session tasks.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;

use crate::transport::{HttpAcceptor, TransportError};

use super::Epoch;
use super::config::ServeConfig;
use super::sequencer::{Metrics, Sequencer};
use super::session::{self, SessionContext};

/// Why the server could not start.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Binding the listener failed.
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
}

/// A bound server: listener, actor and ticker.
#[derive(Debug)]
pub struct Server {
    config: Arc<ServeConfig>,
    acceptor: HttpAcceptor,
    sequencer: Sequencer,
    metrics: Arc<Metrics>,
    actor: JoinHandle<()>,
    ticker: JoinHandle<()>,
}

impl Server {
    /// Bind the listener and start the actor.
    ///
    /// Binding is the only fallible step. Nothing is loaded from disk: the
    /// epoch is fresh and the sequence starts at zero.
    pub async fn bind(config: ServeConfig) -> Result<Self, ServerError> {
        let config = Arc::new(config);
        let epoch = Epoch::generate();
        let metrics = Arc::new(Metrics::new(epoch));
        let (sequencer, actor) = Sequencer::start(Arc::clone(&config), epoch, Arc::clone(&metrics));
        let health_metrics = Arc::clone(&metrics);
        let acceptor = HttpAcceptor::bind(config.listen, &config.namespace)
            .await?
            .with_healthz(move || health_metrics.healthz());
        let ticker = spawn_ticker(sequencer.clone(), config.tick_interval);
        Ok(Self {
            config,
            acceptor,
            sequencer,
            metrics,
            actor,
            ticker,
        })
    }

    /// Bound address, including the ephemeral port chosen by the OS.
    pub fn local_addr(&self) -> Result<SocketAddr, ServerError> {
        Ok(self.acceptor.local_addr()?)
    }

    /// Actor handle, for tests and for W10's relay hub.
    pub fn sequencer(&self) -> Sequencer {
        self.sequencer.clone()
    }

    /// Atomic mirrors read by `healthz`.
    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }

    /// Run until the listener closes.
    pub async fn run(self) {
        self.run_with_shutdown(std::future::pending()).await;
    }

    /// Run the accept loop until `shutdown` resolves, then stop the actor.
    pub async fn run_with_shutdown(self, shutdown: impl Future<Output = ()>) {
        let Self {
            config,
            acceptor,
            sequencer,
            metrics: _metrics,
            actor,
            ticker,
        } = self;
        let context = SessionContext {
            sequencer: sequencer.clone(),
            config,
        };
        let mut acceptor = acceptor;
        let accept = async {
            loop {
                match acceptor.accept_http().await {
                    Ok(accepted) => session::spawn(accepted, context.clone()),
                    Err(TransportError::Closed) => break,
                    Err(_) => continue,
                }
            }
        };
        tokio::select! {
            _ = shutdown => {}
            _ = accept => {}
        }
        let _ = sequencer.shutdown().await;
        let _ = actor.await;
        ticker.abort();
    }

    /// Stop a server that is not running an accept loop.
    pub async fn shutdown(self) {
        let Self {
            sequencer,
            actor,
            ticker,
            ..
        } = self;
        let _ = sequencer.shutdown().await;
        let _ = actor.await;
        ticker.abort();
    }
}

fn spawn_ticker(sequencer: Sequencer, period: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if sequencer.tick(Instant::now()).await.is_err() {
                break;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::protocol::{
        Caps, ClientId, CtrlPrefix, Flags, FrameBuf, FrameDecoder, FrameHeader, FrameRef, Hello,
        Limits, Message, MsgType, Prefix, ProtoVersion, Seq, decode_plain, encode_frame,
    };
    use crate::server::config::OutboxConfig;
    use crate::server::online::Outbox;
    use crate::server::sequencer::{HelloRequest, encode_control};
    use crate::transport::{DialOptions, Endpoint, HttpTransport, PeerId};
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::oneshot;

    async fn get_healthz(addr: SocketAddr) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                b"GET /__syncmount/healthz HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        let text = String::from_utf8_lossy(&response).into_owned();
        text.split("\r\n\r\n").nth(1).unwrap_or_default().to_owned()
    }

    fn ordered_frame() -> FrameBuf {
        let body = vec![0x5a; 30];
        let mut header = FrameHeader::new(MsgType::ORDERED, Flags::ENC, 0, Seq::UNSEQUENCED);
        header.len = u32::try_from(body.len()).unwrap();
        FrameBuf::new(header, Prefix::None, body)
    }

    async fn attach(
        sequencer: &Sequencer,
        client: ClientId,
        nonce: u64,
    ) -> crate::server::HelloReply {
        let (outbox, data, ctrl) = Outbox::new(&OutboxConfig {
            cap_bytes: 64 * 1024 * 1024,
            cap_frames: 20_000,
            data_frames: 20_000,
            ctrl_frames: 64,
        });
        sequencer
            .hello(HelloRequest {
                nonce,
                client_id: client,
                epoch_seen: sequencer.epoch().get(),
                applied_seq: Seq::UNSEQUENCED,
                peer: PeerId::from_serial(nonce),
                outbox,
                data,
                ctrl,
            })
            .await
            .unwrap()
    }

    fn decode_one(bytes: &[u8]) -> FrameBuf {
        let mut decoder = FrameDecoder::new(Limits::default());
        decoder.push(bytes).unwrap();
        decoder.next_frame_owned().unwrap().unwrap()
    }

    #[tokio::test]
    async fn server_healthz_reports_fixed_fields_and_live_counters() {
        let server = Server::bind(ServeConfig::for_tests()).await.unwrap();
        let addr = server.local_addr().unwrap();
        let sequencer = server.sequencer();
        let (stop_tx, stop_rx) = oneshot::channel();
        let task = tokio::spawn(server.run_with_shutdown(async {
            let _ = stop_rx.await;
        }));

        let empty = get_healthz(addr).await;
        for field in [
            "\"status\":\"ok\"",
            "\"version\":\"",
            "\"mode\":\"serve\"",
            "\"clients\":0",
            "\"uptime_s\":",
            "\"seq\":0",
            "\"epoch\":\"0x",
            "\"sync_sessions\":0",
        ] {
            assert!(empty.contains(field), "missing {field} in {empty}");
        }

        let client = ClientId::from_bytes([7; 16]);
        let _reply = attach(&sequencer, client, 1).await;
        for _ in 0..3 {
            sequencer.ordered(client, ordered_frame()).await.unwrap();
        }
        // The snapshot is ordered after the three commands on the same
        // channel, so it also proves the actor finished them.
        let snapshot = sequencer.snapshot().await.unwrap();
        assert_eq!(snapshot.clients, 1, "attach must keep the session online");
        assert_eq!(snapshot.current_seq, Seq(3));

        let live = get_healthz(addr).await;
        eprintln!("W9 evidence: healthz {live}");
        assert!(live.contains("\"clients\":1"), "{live}");
        assert!(live.contains("\"seq\":3"), "{live}");
        assert!(live.contains("\"sync_sessions\":0"), "{live}");

        let _ = stop_tx.send(());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn server_http_rpc_events_handshake_sequences_ordered() {
        let server = Server::bind(ServeConfig::for_tests()).await.unwrap();
        let addr = server.local_addr().unwrap();
        let (stop_tx, stop_rx) = oneshot::channel();
        let task = tokio::spawn(server.run_with_shutdown(async {
            let _ = stop_rx.await;
        }));

        let endpoint = Endpoint::parse(&format!("http://{addr}/")).unwrap();
        let options = DialOptions::random();
        let mut transport = tokio::time::timeout(
            Duration::from_secs(2),
            HttpTransport::dial(&endpoint, &options),
        )
        .await
        .unwrap()
        .unwrap();

        let hello = Hello::new(
            ProtoVersion::CURRENT,
            Caps::REQUIRED,
            ClientId::from_bytes([9; 16]),
            [7; 32],
        );
        let hello_body = hello.encode().unwrap();
        let hello_frame = encode_control(
            MsgType::HELLO,
            Prefix::Ctrl(CtrlPrefix::new(Seq::UNSEQUENCED, 0)),
            &hello_body,
            Seq::UNSEQUENCED,
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), transport.send(hello_frame))
            .await
            .unwrap()
            .unwrap();

        let welcome_bytes = tokio::time::timeout(Duration::from_secs(2), transport.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let welcome = decode_one(&welcome_bytes);
        assert_eq!(welcome.header.msg_type, MsgType::WELCOME);
        match decode_plain(MsgType::WELCOME, &welcome.body, &Limits::default()).unwrap() {
            Message::Welcome(welcome) => {
                assert_eq!(welcome.client_id, ClientId::from_bytes([9; 16]));
                assert_eq!(welcome.current_seq, Seq::UNSEQUENCED);
            }
            other => panic!("expected WELCOME, got {other:?}"),
        }

        let ordered = ordered_frame();
        let ordered_bytes = encode_frame(&FrameRef::new(
            &ordered.header,
            &ordered.prefix,
            &ordered.body,
        ))
        .unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            transport.send(Bytes::from(ordered_bytes)),
        )
        .await
        .unwrap()
        .unwrap();

        let broadcast_bytes = tokio::time::timeout(Duration::from_secs(2), transport.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let broadcast = decode_one(&broadcast_bytes);
        assert_eq!(broadcast.header.msg_type, MsgType::ORDERED);
        assert_eq!(broadcast.header.seq, Seq(1));
        eprintln!(
            "W9 evidence: HTTP rpc/events paired; WELCOME client={:?}; first ORDERED seq={:?}",
            ClientId::from_bytes([9; 16]),
            broadcast.header.seq
        );

        transport.close().await.unwrap();
        let _ = stop_tx.send(());
        task.await.unwrap();
    }
}
