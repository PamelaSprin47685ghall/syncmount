//! HTTP surface and process lifecycle.
//!
//! [`Server::bind`] opens the SQLite store, derives the PSK ring, assembles
//! the actor and the acceptor. [`Server::run_with_shutdown`] owns the accept
//! loop; `healthz` is served by the acceptor's synchronous closure, so a
//! probe never waits on the actor.
//!
//! Graceful shutdown is: drain (wait for every applied watermark to reach
//! `current_seq`, bounded), compact (epoch + 1, seq 0, new replayable log),
//! kick every session with `EpochMismatch`, then stop. A crash skips the
//! compaction; the next start resumes `epoch`/`seq` from `meta`.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;

use crate::crypto::secret::MasterKey;
use crate::protocol::crypto::PskSalt;
use crate::transport::{HttpAcceptor, TransportError};

use super::Epoch;
use super::config::ServeConfig;
use super::metrics::Metrics;
use super::sequencer::Sequencer;
use super::session::{self, SessionContext};
use super::store::{StoreHandle, StoreMeta};

/// Why the server could not start.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Binding the listener failed.
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    /// Opening the SQLite store failed.
    #[error("store: {0}")]
    Store(String),
    /// Deriving the PSK ring failed.
    #[error("key derivation: {0}")]
    Secret(String),
}

/// A bound server: listener, actor and ticker.
#[derive(Debug)]
pub struct Server {
    config: Arc<ServeConfig>,
    acceptor: HttpAcceptor,
    sequencer: Sequencer,
    metrics: Arc<Metrics>,
    store: StoreHandle,
    master: Arc<MasterKey>,
    actor: JoinHandle<()>,
    ticker: JoinHandle<()>,
}

impl Server {
    /// Open the store, bind the listener and start the actor.
    pub async fn bind(config: ServeConfig, master: MasterKey) -> Result<Self, ServerError> {
        let config = Arc::new(config);
        let path = config.db_path.clone();
        let (store, meta): (StoreHandle, StoreMeta) =
            tokio::task::spawn_blocking(move || StoreHandle::start(path))
                .await
                .map_err(|error| ServerError::Store(format!("store thread: {error}")))?
                .map_err(ServerError::Store)?;
        let master = Arc::new(master);
        let ring = Arc::new(
            master
                .derive_psk_keyring(&PskSalt::DEFAULT)
                .map_err(|error| ServerError::Secret(error.to_string()))?,
        );
        let epoch = Epoch::new(meta.epoch.max(1) as u64);
        let metrics = Arc::new(Metrics::new(epoch));
        let (sequencer, actor) = Sequencer::start(
            Arc::clone(&config),
            meta,
            store.clone(),
            ring,
            Arc::clone(&metrics),
        );
        let health_metrics = Arc::clone(&metrics);
        let acceptor = match HttpAcceptor::bind(config.listen, &config.namespace).await {
            Ok(acceptor) => acceptor.with_healthz(move || health_metrics.healthz()),
            Err(error) => {
                let _ = store.shutdown().await;
                return Err(error.into());
            }
        };
        let ticker = spawn_ticker(sequencer.clone(), config.tick_interval);
        Ok(Self {
            config,
            acceptor,
            sequencer,
            metrics,
            store,
            master,
            actor,
            ticker,
        })
    }

    /// Bound address, including the ephemeral port chosen by the OS.
    pub fn local_addr(&self) -> Result<SocketAddr, ServerError> {
        Ok(self.acceptor.local_addr()?)
    }

    /// Actor handle, for tests and diagnostics.
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

    /// Run the accept loop until `shutdown` resolves, then drain, compact and
    /// stop the actor.
    pub async fn run_with_shutdown(self, shutdown: impl Future<Output = ()>) {
        let Self {
            config,
            acceptor,
            sequencer,
            metrics: _metrics,
            store,
            master,
            actor,
            ticker,
        } = self;
        let context = SessionContext {
            sequencer: sequencer.clone(),
            config: Arc::clone(&config),
            master,
            guard: Arc::new(tokio::sync::Mutex::new(
                crate::protocol::handshake::NonceReplayGuard::new(),
            )),
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
        let drain = sequencer.drain(config.drain_timeout).await;
        match drain {
            Ok(report) if report.timed_out => {
                tracing::warn!(
                    sessions = report.sessions,
                    applied_min = report.applied_min.get(),
                    current = report.current_seq.get(),
                    "drain timed out; compacting anyway"
                );
            }
            Ok(report) => {
                tracing::info!(
                    sessions = report.sessions,
                    seq = report.current_seq.get(),
                    "drain complete"
                );
            }
            Err(_) => {}
        }
        match sequencer.compact().await {
            Ok(report) => {
                tracing::info!(
                    epoch = report.epoch,
                    events = report.events,
                    objects = report.objects,
                    "event log compacted"
                );
            }
            Err(error) => tracing::error!(%error, "compaction failed"),
        }
        let _ = sequencer.shutdown().await;
        let _ = actor.await;
        ticker.abort();
        if let Err(error) = store.shutdown().await {
            tracing::error!(%error, "store shutdown failed");
        }
    }

    /// Stop a server that is not running an accept loop.
    pub async fn shutdown(self) {
        let Self {
            sequencer,
            store,
            actor,
            ticker,
            ..
        } = self;
        let _ = sequencer.shutdown().await;
        let _ = actor.await;
        ticker.abort();
        let _ = store.shutdown().await;
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

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

    fn master() -> MasterKey {
        MasterKey::derive_psk_from_password(b"test-master", &PskSalt::DEFAULT).unwrap()
    }

    #[tokio::test]
    async fn server_healthz_reports_fixed_fields_and_live_counters() {
        let server = Server::bind(ServeConfig::for_tests(), master())
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
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

        let _ = stop_tx.send(());
        task.await.unwrap();
    }
}
