//! 内存传输：确定性、有界、可分区。
//!
//! [`InMemoryHub`] 实现字节级 [`Transport`] 端口。每次 `dial` 产生一对半边：
//! 客户端半边返回给拨号方，服务端半边进入 [`Acceptor`] 队列。peer 由
//! [`DialOptions::nonce`] 派生，因此同一会话的两条流共享同一个 peer；配对本身
//! 仍由服务层按 nonce 完成，本模块不解释任何帧。
//!
//! 三条不变量：
//! - 每个接收方向只有一个容量为 `queue_cap` 的队列，发送方在队列满时等待；
//! - 延迟由 [`HubConfig`] 与自包含的 SplitMix64 决定，同一 seed、同一拨号顺序
//!   与同一发送序列必然得到同一延迟序列；
//! - `partition` 关闭该 peer 的全部活动连接，`heal` 只清除标记；旧传输不复活。

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, watch};

use super::faults::SplitMix64;
use crate::transport::{
    AcceptedConn, Acceptor, BoxFut, DialOptions, Dialer, Endpoint, PeerId, StreamKind, Transport,
    TransportError,
};

/// 接受队列深度：等待服务层取走的半边数量。
const ACCEPT_QUEUE_DEPTH: usize = 64;

/// 内存网络参数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HubConfig {
    /// 每个接收方向的队列容量（块数）；小于 1 时按 1 处理。
    pub queue_cap: usize,
    /// 延迟随机源的种子。
    pub seed: u64,
    /// 单块最大字节数；超出的 `send` 被拒绝。
    pub max_frame: usize,
    /// 最小投递延迟。
    pub base_latency: Duration,
    /// 附加抖动；实际延迟落在 `[base_latency, base_latency + jitter]`。
    pub jitter: Duration,
}

impl Default for HubConfig {
    fn default() -> Self {
        Self {
            queue_cap: 64,
            seed: 0,
            max_frame: 128 * 1024,
            base_latency: Duration::ZERO,
            jitter: Duration::ZERO,
        }
    }
}

/// 内存网络统计快照。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HubStats {
    /// 成功交给对端队列的块数。
    pub frames_sent: u64,
    /// `recv` 取出的块数。
    pub frames_recv: u64,
    /// 因关闭或分区丢弃的块数。
    pub frames_dropped: u64,
    /// 成功投递的字节数。
    pub bytes_sent: u64,
    /// 取出的字节数。
    pub bytes_recv: u64,
    /// 观察到的最大队列占用。
    pub max_queue_depth: usize,
    /// 每块投递对应的延迟样本，按投递顺序排列。
    pub latency_samples: Vec<Duration>,
}

/// 内存网络中枢。
///
/// [`MemNet`] 是同一类型的短别名，供只关心“内存网络”的测试使用。
pub struct InMemoryHub {
    inner: Arc<HubInner>,
    accept_tx: Mutex<Option<mpsc::Sender<AcceptedConn>>>,
    acceptor: Arc<AcceptorQueue>,
}

impl InMemoryHub {
    /// 创建中枢；`queue_cap` 与 `max_frame` 至少为 1。
    pub fn new(cfg: HubConfig) -> Arc<Self> {
        let cfg = HubConfig {
            queue_cap: cfg.queue_cap.max(1),
            max_frame: cfg.max_frame.max(1),
            ..cfg
        };
        let (accept_tx, accept_rx) = mpsc::channel(ACCEPT_QUEUE_DEPTH);
        Arc::new(Self {
            inner: Arc::new(HubInner {
                cfg,
                stats: Mutex::new(HubStats::default()),
                next_serial: AtomicU64::new(0),
                connections: Mutex::new(HashMap::new()),
                partitioned: Mutex::new(HashSet::new()),
            }),
            accept_tx: Mutex::new(Some(accept_tx)),
            acceptor: Arc::new(AcceptorQueue {
                rx: tokio::sync::Mutex::new(accept_rx),
            }),
        })
    }

    /// 创建拨号器；它持有中枢的强引用。
    pub fn dialer(self: &Arc<Self>) -> Arc<dyn Dialer> {
        Arc::new(HubDialer {
            hub: Arc::clone(self),
        })
    }

    /// 创建接受器；它不持有中枢的强引用，中枢被丢弃时返回
    /// [`TransportError::Closed`]。
    pub fn acceptor(self: &Arc<Self>) -> Arc<dyn Acceptor> {
        Arc::new(HubAcceptor {
            queue: Arc::clone(&self.acceptor),
        })
    }

    /// 标记 peer 为分区，并关闭它的全部活动连接。
    pub fn partition(&self, peer: PeerId) {
        self.inner.partition(peer);
    }

    /// 清除分区标记。旧连接保持关闭，后续 dial 可以重新建立连接。
    pub fn heal(&self, peer: PeerId) {
        self.inner.heal(peer);
    }

    /// 统计快照。
    pub fn stats(&self) -> HubStats {
        self.inner.stats()
    }

    /// 当前仍有活动连接的 peer 数。同一 nonce 的两条流算一个 peer。
    pub fn connected(&self) -> usize {
        self.inner.connected()
    }

    /// peer 是否处于分区状态。
    pub fn is_partitioned(&self, peer: PeerId) -> bool {
        self.inner.is_partitioned(peer)
    }
}

impl fmt::Debug for InMemoryHub {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let partitioned = lock(&self.inner.partitioned).len();
        formatter
            .debug_struct("InMemoryHub")
            .field("config", &self.inner.cfg)
            .field("connected", &self.connected())
            .field("partitioned", &partitioned)
            .finish()
    }
}

/// 内存网络的短别名。
pub type MemNet = InMemoryHub;

impl Drop for InMemoryHub {
    fn drop(&mut self) {
        self.inner.close_all();
        let _ = lock(&self.accept_tx).take();
    }
}

/// 中枢共享状态。
struct HubInner {
    cfg: HubConfig,
    stats: Mutex<HubStats>,
    next_serial: AtomicU64,
    connections: Mutex<HashMap<PeerId, Vec<Arc<ConnRecord>>>>,
    partitioned: Mutex<HashSet<PeerId>>,
}

impl HubInner {
    /// 本次投递的延迟。种子、连接序号与帧序号共同决定结果。
    fn latency(&self, serial: u64, frame_index: u64) -> Duration {
        let cfg = self.cfg;
        if cfg.jitter.is_zero() {
            return cfg.base_latency;
        }
        let mut rng = SplitMix64::new(mix_seed(cfg.seed, serial, frame_index));
        let jitter_ns = u64::try_from(cfg.jitter.as_nanos()).unwrap_or(u64::MAX);
        let span = jitter_ns.saturating_add(1);
        let extra = rng.next_u64() % span;
        cfg.base_latency.saturating_add(Duration::from_nanos(extra))
    }

    fn record_delivered(&self, bytes: usize, delay: Duration, depth: usize) {
        let mut stats = lock(&self.stats);
        stats.frames_sent = stats.frames_sent.saturating_add(1);
        stats.bytes_sent = stats.bytes_sent.saturating_add(bytes as u64);
        stats.max_queue_depth = stats.max_queue_depth.max(depth);
        stats.latency_samples.push(delay);
    }

    fn record_received(&self, bytes: usize) {
        let mut stats = lock(&self.stats);
        stats.frames_recv = stats.frames_recv.saturating_add(1);
        stats.bytes_recv = stats.bytes_recv.saturating_add(bytes as u64);
    }

    fn record_dropped(&self, frames: u64) {
        let mut stats = lock(&self.stats);
        stats.frames_dropped = stats.frames_dropped.saturating_add(frames);
    }

    fn stats(&self) -> HubStats {
        lock(&self.stats).clone()
    }

    fn register(&self, record: Arc<ConnRecord>) {
        lock(&self.connections)
            .entry(record.peer)
            .or_default()
            .push(record);
    }

    fn partition(&self, peer: PeerId) {
        let _ = lock(&self.partitioned).insert(peer);
        let records = {
            let connections = lock(&self.connections);
            connections.get(&peer).cloned().unwrap_or_default()
        };
        for record in records {
            record.close();
        }
    }

    fn heal(&self, peer: PeerId) {
        let _ = lock(&self.partitioned).remove(&peer);
    }

    fn is_partitioned(&self, peer: PeerId) -> bool {
        lock(&self.partitioned).contains(&peer)
    }

    fn connected(&self) -> usize {
        lock(&self.connections)
            .values()
            .filter(|records| records.iter().any(|record| record.is_live()))
            .count()
    }

    fn close_all(&self) {
        let records: Vec<Arc<ConnRecord>> = {
            let connections = lock(&self.connections);
            connections.values().flatten().cloned().collect()
        };
        for record in records {
            record.close();
        }
    }
}

/// 一次 `dial` 产生的连接记录。两条流各自一条记录，但共享同一个 peer。
struct ConnRecord {
    peer: PeerId,
    halves: [Arc<HalfRecord>; 2],
}

impl ConnRecord {
    fn is_live(&self) -> bool {
        self.halves
            .iter()
            .any(|half| !half.closed.load(Ordering::SeqCst))
    }

    fn close(&self) {
        for half in &self.halves {
            half.close();
        }
    }
}

/// 半边状态：关闭标记、唤醒信号与接收队列占用。
struct HalfRecord {
    closed: AtomicBool,
    signal: watch::Sender<bool>,
    hub: Weak<HubInner>,
    queued: Option<Arc<AtomicUsize>>,
}

impl HalfRecord {
    fn new(
        hub: &Arc<HubInner>,
        queued: Option<Arc<AtomicUsize>>,
    ) -> (Arc<Self>, watch::Receiver<bool>) {
        let (signal, receiver) = watch::channel(false);
        (
            Arc::new(Self {
                closed: AtomicBool::new(false),
                signal,
                hub: Arc::downgrade(hub),
                queued,
            }),
            receiver,
        )
    }

    /// 关闭半边；幂等。接收方向把排队中的块计入丢弃数。
    fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = self.signal.send(true);
        if let Some(depth) = &self.queued {
            let dropped = depth.swap(0, Ordering::SeqCst);
            if dropped > 0 {
                if let Some(hub) = self.hub.upgrade() {
                    hub.record_dropped(u64::try_from(dropped).unwrap_or(u64::MAX));
                }
            }
        }
    }
}

/// 接受队列。多个 [`Acceptor`] 共享同一个接收端，依次取走连接。
struct AcceptorQueue {
    rx: tokio::sync::Mutex<mpsc::Receiver<AcceptedConn>>,
}

/// 内存拨号器。
struct HubDialer {
    hub: Arc<InMemoryHub>,
}

impl Dialer for HubDialer {
    fn dial<'a>(
        &'a self,
        _endpoint: &'a Endpoint,
        kind: StreamKind,
        options: &'a DialOptions,
    ) -> BoxFut<'a, Result<Box<dyn Transport>, TransportError>> {
        Box::pin(async move {
            let hub = &self.hub;
            let peer = PeerId::from_serial(options.nonce);
            if hub.inner.is_partitioned(peer) {
                return Err(TransportError::Disconnected);
            }
            let serial = hub.inner.next_serial.fetch_add(1, Ordering::SeqCst);
            let cfg = hub.inner.cfg;
            let depth = Arc::new(AtomicUsize::new(0));

            let (tx, rx) = mpsc::channel::<Bytes>(cfg.queue_cap);
            let (client_tx, client_rx, server_tx, server_rx) = match kind {
                StreamKind::Rpc => (Some(tx), None, None, Some(rx)),
                StreamKind::Events => (None, Some(rx), Some(tx), None),
            };
            let (client_half, client_closed) = HalfRecord::new(
                &hub.inner,
                match kind {
                    StreamKind::Rpc => None,
                    StreamKind::Events => Some(Arc::clone(&depth)),
                },
            );
            let (server_half, server_closed) = HalfRecord::new(
                &hub.inner,
                match kind {
                    StreamKind::Rpc => Some(Arc::clone(&depth)),
                    StreamKind::Events => None,
                },
            );
            hub.inner.register(Arc::new(ConnRecord {
                peer,
                halves: [Arc::clone(&client_half), Arc::clone(&server_half)],
            }));

            let client = InMemoryTransport {
                side: Side::Client,
                kind,
                peer,
                serial,
                frame_index: 0,
                max_frame: cfg.max_frame,
                hub: Arc::clone(&hub.inner),
                closed: client_closed,
                tx: client_tx,
                rx: client_rx,
                queue_depth: Arc::clone(&depth),
                half: client_half,
            };
            let server = InMemoryTransport {
                side: Side::Server,
                kind,
                peer,
                serial,
                frame_index: 0,
                max_frame: cfg.max_frame,
                hub: Arc::clone(&hub.inner),
                closed: server_closed,
                tx: server_tx,
                rx: server_rx,
                queue_depth: depth,
                half: server_half,
            };

            let accepted = AcceptedConn {
                peer,
                kind,
                nonce: options.nonce,
                client_id: options.client_id,
                transport: Box::new(server),
            };
            let accept_tx = {
                let guard = lock(&hub.accept_tx);
                guard.as_ref().cloned()
            };
            let Some(accept_tx) = accept_tx else {
                return Err(TransportError::Closed);
            };
            if accept_tx.send(accepted).await.is_err() {
                return Err(TransportError::Closed);
            }
            Ok(Box::new(client) as Box<dyn Transport>)
        })
    }
}

/// 内存接受器。
struct HubAcceptor {
    queue: Arc<AcceptorQueue>,
}

impl Acceptor for HubAcceptor {
    fn accept(&self) -> BoxFut<'_, Result<AcceptedConn, TransportError>> {
        Box::pin(async move {
            let mut rx = self.queue.rx.lock().await;
            rx.recv().await.ok_or(TransportError::Closed)
        })
    }
}

/// 半边角色。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Client,
    Server,
}

impl Side {
    const fn can_send(self, kind: StreamKind) -> bool {
        matches!(
            (self, kind),
            (Self::Client, StreamKind::Rpc) | (Self::Server, StreamKind::Events)
        )
    }

    const fn can_recv(self, kind: StreamKind) -> bool {
        matches!(
            (self, kind),
            (Self::Client, StreamKind::Events) | (Self::Server, StreamKind::Rpc)
        )
    }
}

/// 内存传输的一个半边。
pub struct InMemoryTransport {
    side: Side,
    kind: StreamKind,
    peer: PeerId,
    serial: u64,
    frame_index: u64,
    max_frame: usize,
    hub: Arc<HubInner>,
    closed: watch::Receiver<bool>,
    tx: Option<mpsc::Sender<Bytes>>,
    rx: Option<mpsc::Receiver<Bytes>>,
    queue_depth: Arc<AtomicUsize>,
    half: Arc<HalfRecord>,
}

impl InMemoryTransport {
    /// 关闭本半边：通知等待者，并丢弃两个方向的通道端点。
    fn shutdown(&mut self) {
        self.half.close();
        self.tx = None;
        self.rx = None;
    }
}

impl fmt::Debug for InMemoryTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryTransport")
            .field("side", &self.side)
            .field("kind", &self.kind)
            .field("peer", &self.peer)
            .field("serial", &self.serial)
            .field("closed", &self.half.closed.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl Drop for InMemoryTransport {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl Transport for InMemoryTransport {
    fn send(&mut self, chunk: Bytes) -> BoxFut<'_, Result<(), TransportError>> {
        Box::pin(async move {
            if !self.side.can_send(self.kind) {
                return Err(TransportError::WrongDirection(self.kind, "send"));
            }
            if chunk.len() > self.max_frame {
                return Err(TransportError::Http(format!(
                    "frame exceeds max_frame: {} > {}",
                    chunk.len(),
                    self.max_frame
                )));
            }
            if *self.closed.borrow() {
                return Err(TransportError::Disconnected);
            }
            let Some(tx) = self.tx.clone() else {
                return Err(TransportError::Disconnected);
            };

            let frame_index = self.frame_index;
            self.frame_index = self.frame_index.wrapping_add(1);
            let delay = self.hub.latency(self.serial, frame_index);
            if !delay.is_zero() {
                let sleep = tokio::time::sleep(delay);
                tokio::pin!(sleep);
                tokio::select! {
                    () = &mut sleep => {}
                    _ = self.closed.changed() => {
                        self.hub.record_dropped(1);
                        return Err(TransportError::Disconnected);
                    }
                }
            }
            if *self.closed.borrow() {
                self.hub.record_dropped(1);
                return Err(TransportError::Disconnected);
            }

            let bytes = chunk.len();
            tokio::select! {
                result = tx.send(chunk) => match result {
                    Ok(()) => {
                        let depth = self
                            .queue_depth
                            .fetch_add(1, Ordering::SeqCst)
                            .saturating_add(1);
                        self.hub.record_delivered(bytes, delay, depth);
                        Ok(())
                    }
                    Err(_) => {
                        self.hub.record_dropped(1);
                        Err(TransportError::Disconnected)
                    }
                },
                _ = self.closed.changed() => {
                    self.hub.record_dropped(1);
                    Err(TransportError::Disconnected)
                }
            }
        })
    }

    fn recv(&mut self) -> BoxFut<'_, Result<Option<Bytes>, TransportError>> {
        Box::pin(async move {
            if !self.side.can_recv(self.kind) {
                return Err(TransportError::WrongDirection(self.kind, "recv"));
            }
            if *self.closed.borrow() {
                return Ok(None);
            }
            let Some(rx) = self.rx.as_mut() else {
                return Ok(None);
            };
            tokio::select! {
                item = rx.recv() => match item {
                    Some(chunk) => {
                        let _ = self.queue_depth.fetch_update(
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                            |depth| Some(depth.saturating_sub(1)),
                        );
                        self.hub.record_received(chunk.len());
                        Ok(Some(chunk))
                    }
                    None => Ok(None),
                },
                _ = self.closed.changed() => Ok(None),
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

/// 锁定互斥量；中毒时取回内部值，绝不 panic。
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// 把 `(seed, serial, frame_index)` 混合成一个新的 SplitMix64 种子。
fn mix_seed(seed: u64, serial: u64, frame_index: u64) -> u64 {
    let mut rng = SplitMix64::new(seed ^ serial.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let first = rng.next_u64();
    let second = rng.next_u64();
    first ^ second.rotate_left(32) ^ frame_index.wrapping_mul(0xD6E8_FEB8_6659_FD93)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;

    use super::{HubConfig, HubStats, InMemoryHub};
    use crate::transport::{
        Acceptor, DialOptions, Endpoint, PeerId, StreamKind, Transport, TransportError,
    };

    const TEST_TIMEOUT: Duration = Duration::from_secs(1);
    const PENDING: Duration = Duration::from_millis(1);

    async fn within<T>(future: impl Future<Output = T>) -> T {
        tokio::time::timeout(TEST_TIMEOUT, future)
            .await
            .expect("memnet test operation timed out")
    }

    fn endpoint() -> Endpoint {
        Endpoint::parse("http://127.0.0.1:1/ns").expect("valid test endpoint")
    }

    async fn accept(
        acceptor: &Arc<dyn Acceptor>,
        kind: StreamKind,
        nonce: u64,
    ) -> Box<dyn Transport> {
        let conn = within(acceptor.accept()).await.unwrap();
        assert_eq!(conn.kind, kind);
        assert_eq!(conn.nonce, nonce);
        conn.transport
    }

    /// W18: two clients share one hub; each session is independent.
    #[tokio::test(start_paused = true)]
    async fn u_testkit_memnet_dual_client_roundtrip() {
        let hub = InMemoryHub::new(HubConfig::default());
        let endpoint = endpoint();
        let dialer = hub.dialer();
        let acceptor = hub.acceptor();
        let options_a = DialOptions::new(0xA11CE);
        let options_b = DialOptions::new(0xB0B);

        let mut a_rpc = within(dialer.dial(&endpoint, StreamKind::Rpc, &options_a))
            .await
            .unwrap();
        let mut a_events = within(dialer.dial(&endpoint, StreamKind::Events, &options_a))
            .await
            .unwrap();
        let mut b_rpc = within(dialer.dial(&endpoint, StreamKind::Rpc, &options_b))
            .await
            .unwrap();
        let mut b_events = within(dialer.dial(&endpoint, StreamKind::Events, &options_b))
            .await
            .unwrap();

        let mut server_a_rpc = accept(&acceptor, StreamKind::Rpc, options_a.nonce).await;
        let mut server_a_events = accept(&acceptor, StreamKind::Events, options_a.nonce).await;
        let mut server_b_rpc = accept(&acceptor, StreamKind::Rpc, options_b.nonce).await;
        let mut server_b_events = accept(&acceptor, StreamKind::Events, options_b.nonce).await;

        within(a_rpc.send(Bytes::from_static(b"ping")))
            .await
            .unwrap();
        assert_eq!(
            within(server_a_rpc.recv()).await.unwrap(),
            Some(Bytes::from_static(b"ping"))
        );
        within(server_a_events.send(Bytes::from_static(b"pong")))
            .await
            .unwrap();
        assert_eq!(
            within(a_events.recv()).await.unwrap(),
            Some(Bytes::from_static(b"pong"))
        );

        assert!(
            tokio::time::timeout(PENDING, server_b_rpc.recv())
                .await
                .is_err(),
            "client B's uplink must stay empty"
        );
        assert!(
            tokio::time::timeout(PENDING, b_events.recv())
                .await
                .is_err(),
            "client B's downlink must stay empty"
        );

        within(b_rpc.send(Bytes::from_static(b"b-ping")))
            .await
            .unwrap();
        assert_eq!(
            within(server_b_rpc.recv()).await.unwrap(),
            Some(Bytes::from_static(b"b-ping"))
        );
        within(server_b_events.send(Bytes::from_static(b"b-pong")))
            .await
            .unwrap();
        assert_eq!(
            within(b_events.recv()).await.unwrap(),
            Some(Bytes::from_static(b"b-pong"))
        );
        assert!(
            tokio::time::timeout(PENDING, server_a_rpc.recv())
                .await
                .is_err(),
            "client A's uplink must not receive client B's bytes"
        );
        assert!(
            tokio::time::timeout(PENDING, a_events.recv())
                .await
                .is_err(),
            "client A's downlink must not receive client B's bytes"
        );
        assert_eq!(hub.connected(), 2);
    }

    /// W18: accepted metadata carries the dial options; directions are enforced.
    #[tokio::test]
    async fn u_testkit_memnet_pairing_metadata() {
        let hub = InMemoryHub::new(HubConfig::default());
        let endpoint = endpoint();
        let dialer = hub.dialer();
        let acceptor = hub.acceptor();
        let options = DialOptions::new(0xDEAD_BEEF).with_client_id([7; 16]);
        let peer = PeerId::from_serial(options.nonce);

        let mut client_rpc = within(dialer.dial(&endpoint, StreamKind::Rpc, &options))
            .await
            .unwrap();
        let mut client_events = within(dialer.dial(&endpoint, StreamKind::Events, &options))
            .await
            .unwrap();
        let server_rpc = within(acceptor.accept()).await.unwrap();
        let server_events = within(acceptor.accept()).await.unwrap();

        assert_eq!(server_rpc.kind, StreamKind::Rpc);
        assert_eq!(server_events.kind, StreamKind::Events);
        assert_eq!(server_rpc.nonce, options.nonce);
        assert_eq!(server_events.nonce, options.nonce);
        assert_eq!(server_rpc.client_id, Some([7; 16]));
        assert_eq!(server_events.client_id, Some([7; 16]));
        assert_eq!(server_rpc.peer, peer);
        assert_eq!(server_events.peer, peer);
        assert_eq!(hub.connected(), 1);

        let mut server_rpc = server_rpc.transport;
        let mut server_events = server_events.transport;

        assert!(matches!(
            within(client_events.send(Bytes::from_static(b"x"))).await,
            Err(TransportError::WrongDirection(StreamKind::Events, "send"))
        ));
        assert!(matches!(
            within(client_rpc.recv()).await,
            Err(TransportError::WrongDirection(StreamKind::Rpc, "recv"))
        ));
        assert!(matches!(
            within(server_rpc.send(Bytes::from_static(b"x"))).await,
            Err(TransportError::WrongDirection(StreamKind::Rpc, "send"))
        ));
        assert!(matches!(
            within(server_events.recv()).await,
            Err(TransportError::WrongDirection(StreamKind::Events, "recv"))
        ));

        // The valid directions still work after the rejected calls.
        within(client_rpc.send(Bytes::from_static(b"up")))
            .await
            .unwrap();
        assert_eq!(
            within(server_rpc.recv()).await.unwrap(),
            Some(Bytes::from_static(b"up"))
        );
        within(server_events.send(Bytes::from_static(b"down")))
            .await
            .unwrap();
        assert_eq!(
            within(client_events.recv()).await.unwrap(),
            Some(Bytes::from_static(b"down"))
        );
    }

    /// W18: a full receive queue blocks the sender until the reader drains it.
    #[tokio::test(start_paused = true)]
    async fn u_testkit_memnet_backpressure_bounded() {
        let hub = InMemoryHub::new(HubConfig {
            queue_cap: 1,
            ..HubConfig::default()
        });
        let endpoint = endpoint();
        let dialer = hub.dialer();
        let acceptor = hub.acceptor();
        let options = DialOptions::new(1);

        let mut client = within(dialer.dial(&endpoint, StreamKind::Rpc, &options))
            .await
            .unwrap();
        let mut server = accept(&acceptor, StreamKind::Rpc, options.nonce).await;

        within(client.send(Bytes::from_static(b"first")))
            .await
            .unwrap();
        let mut second = client.send(Bytes::from_static(b"second"));
        assert!(
            tokio::time::timeout(PENDING, &mut second).await.is_err(),
            "second send must wait for queue capacity"
        );

        assert_eq!(
            within(server.recv()).await.unwrap(),
            Some(Bytes::from_static(b"first"))
        );
        within(second).await.unwrap();
        assert_eq!(
            within(server.recv()).await.unwrap(),
            Some(Bytes::from_static(b"second"))
        );
    }

    /// W18: partition closes every stream of a peer; heal only allows new dials.
    #[tokio::test(start_paused = true)]
    async fn u_testkit_memnet_partition_and_heal() {
        let hub = InMemoryHub::new(HubConfig::default());
        let endpoint = endpoint();
        let dialer = hub.dialer();
        let acceptor = hub.acceptor();
        let options = DialOptions::new(0x5151);
        let peer = PeerId::from_serial(options.nonce);

        let mut client_rpc = within(dialer.dial(&endpoint, StreamKind::Rpc, &options))
            .await
            .unwrap();
        let mut client_events = within(dialer.dial(&endpoint, StreamKind::Events, &options))
            .await
            .unwrap();
        let mut server_rpc = accept(&acceptor, StreamKind::Rpc, options.nonce).await;
        let mut server_events = accept(&acceptor, StreamKind::Events, options.nonce).await;
        assert_eq!(hub.connected(), 1);
        assert!(!hub.is_partitioned(peer));

        hub.partition(peer);
        assert!(hub.is_partitioned(peer));
        assert_eq!(hub.connected(), 0);

        assert!(matches!(
            within(client_rpc.send(Bytes::from_static(b"lost"))).await,
            Err(TransportError::Disconnected)
        ));
        assert_eq!(within(server_rpc.recv()).await.unwrap(), None);
        assert_eq!(within(client_events.recv()).await.unwrap(), None);
        assert!(matches!(
            within(server_events.send(Bytes::from_static(b"lost"))).await,
            Err(TransportError::Disconnected)
        ));

        // A partitioned peer cannot dial again until it heals.
        assert!(matches!(
            within(dialer.dial(&endpoint, StreamKind::Rpc, &options)).await,
            Err(TransportError::Disconnected)
        ));

        hub.heal(peer);
        assert!(!hub.is_partitioned(peer));

        // Old transports stay closed after healing.
        assert!(matches!(
            within(client_rpc.send(Bytes::from_static(b"again"))).await,
            Err(TransportError::Disconnected)
        ));
        assert_eq!(within(server_rpc.recv()).await.unwrap(), None);

        // A fresh dial works and reaches the acceptor.
        let mut fresh = within(dialer.dial(&endpoint, StreamKind::Rpc, &options))
            .await
            .unwrap();
        let mut fresh_server = accept(&acceptor, StreamKind::Rpc, options.nonce).await;
        within(fresh.send(Bytes::from_static(b"hello")))
            .await
            .unwrap();
        assert_eq!(
            within(fresh_server.recv()).await.unwrap(),
            Some(Bytes::from_static(b"hello"))
        );
        assert_eq!(hub.connected(), 1);
    }

    /// W18: identical seeds and send sequences produce identical latency samples.
    #[tokio::test(start_paused = true)]
    async fn u_testkit_memnet_deterministic_latency() {
        async fn run(cfg: HubConfig) -> HubStats {
            let hub = InMemoryHub::new(cfg);
            let endpoint = endpoint();
            let dialer = hub.dialer();
            let acceptor = hub.acceptor();
            let options = DialOptions::new(0x1A7E);
            let mut client = within(dialer.dial(&endpoint, StreamKind::Rpc, &options))
                .await
                .unwrap();
            let mut server = accept(&acceptor, StreamKind::Rpc, options.nonce).await;
            for value in 0..8_u8 {
                let chunk = Bytes::from(vec![value]);
                within(client.send(chunk.clone())).await.unwrap();
                assert_eq!(within(server.recv()).await.unwrap(), Some(chunk));
            }
            hub.stats()
        }

        let cfg = HubConfig {
            seed: 0x5EED,
            base_latency: Duration::from_millis(2),
            jitter: Duration::from_millis(5),
            ..HubConfig::default()
        };
        let first = run(cfg).await;
        let second = run(cfg).await;
        assert_eq!(first.latency_samples, second.latency_samples);
        assert_eq!(first.latency_samples.len(), 8);
        let upper = cfg.base_latency + cfg.jitter;
        assert!(
            first
                .latency_samples
                .iter()
                .all(|sample| cfg.base_latency <= *sample && *sample <= upper)
        );
    }

    /// W18: byte, frame, queue-depth and latency counters reflect traffic.
    #[tokio::test(start_paused = true)]
    async fn u_testkit_memnet_stats() {
        let hub = InMemoryHub::new(HubConfig::default());
        let endpoint = endpoint();
        let dialer = hub.dialer();
        let acceptor = hub.acceptor();
        let options = DialOptions::new(7);

        let mut client = within(dialer.dial(&endpoint, StreamKind::Rpc, &options))
            .await
            .unwrap();
        let mut server = accept(&acceptor, StreamKind::Rpc, options.nonce).await;

        within(client.send(Bytes::from_static(b"aa")))
            .await
            .unwrap();
        within(client.send(Bytes::from_static(b"bbb")))
            .await
            .unwrap();
        within(client.send(Bytes::from_static(b"cccc")))
            .await
            .unwrap();

        let sent = hub.stats();
        assert_eq!(sent.frames_sent, 3);
        assert_eq!(sent.bytes_sent, 9);
        assert_eq!(sent.frames_recv, 0);
        assert_eq!(sent.bytes_recv, 0);
        assert_eq!(sent.frames_dropped, 0);
        assert_eq!(sent.max_queue_depth, 3);
        assert_eq!(sent.latency_samples.len(), 3);

        for expected in [
            Bytes::from_static(b"aa"),
            Bytes::from_static(b"bbb"),
            Bytes::from_static(b"cccc"),
        ] {
            assert_eq!(within(server.recv()).await.unwrap(), Some(expected));
        }

        let received = hub.stats();
        assert_eq!(received.frames_sent, 3);
        assert_eq!(received.bytes_sent, 9);
        assert_eq!(received.frames_recv, 3);
        assert_eq!(received.bytes_recv, 9);
        assert_eq!(received.frames_dropped, 0);
        assert_eq!(received.max_queue_depth, 3);
        assert_eq!(hub.connected(), 1);
    }

    /// W18: a chunk larger than `max_frame` is rejected without closing the stream.
    #[tokio::test]
    async fn u_testkit_memnet_max_frame_rejected() {
        let hub = InMemoryHub::new(HubConfig {
            max_frame: 4,
            ..HubConfig::default()
        });
        let endpoint = endpoint();
        let dialer = hub.dialer();
        let acceptor = hub.acceptor();
        let options = DialOptions::new(3);

        let mut client = within(dialer.dial(&endpoint, StreamKind::Rpc, &options))
            .await
            .unwrap();
        let mut server = accept(&acceptor, StreamKind::Rpc, options.nonce).await;

        let error = within(client.send(Bytes::from_static(b"12345")))
            .await
            .unwrap_err();
        match error {
            TransportError::Http(message) => {
                assert!(
                    message.contains("max_frame"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("unexpected error: {other}"),
        }

        within(client.send(Bytes::from_static(b"1234")))
            .await
            .unwrap();
        assert_eq!(
            within(server.recv()).await.unwrap(),
            Some(Bytes::from_static(b"1234"))
        );
    }

    /// W18: dropping the hub wakes a blocked acceptor with `Closed`.
    #[tokio::test(start_paused = true)]
    async fn u_testkit_memnet_drop_wakes_acceptor() {
        let hub = InMemoryHub::new(HubConfig::default());
        let acceptor = hub.acceptor();
        let task = tokio::spawn(async move { acceptor.accept().await });
        tokio::task::yield_now().await;
        drop(hub);
        let outcome = within(task).await.unwrap();
        assert!(matches!(outcome, Err(TransportError::Closed)));
    }
}
