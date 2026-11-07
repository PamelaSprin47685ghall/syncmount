//! 进程内多客户端 harness。
//!
//! 一个 [`Cluster`] 由三部分组成：
//!
//! ```text
//! client A ─┐
//! client B ─┼─ InMemoryHub ─ acceptor ─ 真实 Sequencer actor
//! client C ─┘
//! ```
//!
//! 服务端不是替身：它使用生产 [`Sequencer`]，因此 `HELLO`/`WELCOME`、seq
//! 定序、广播、重复 client id 踢旧留新、detach 都走同一条代码路径。客户端
//! 侧只做握手与帧收发，不复制 `FsCore` 的业务逻辑；需要文件语义的测试在
//! F 层用真实挂载。
//!
//! 与 45 §3.6 的差异是刻意的：本仓库的 `Transport` 是字节端口，客户端
//! `FsCore` 尚未存在，所以 `ClientHandle` 暴露帧级 API 而不是 `write`/
//! `mkdir`。这保证 harness 不伪造第二套业务逻辑。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::protocol::messages::MessageError;
use crate::protocol::{
    Caps, ClientId, CtrlPrefix, FrameBuf, FrameDecoder, FrameHeader, FrameRef, Hello, Limits,
    Message, MsgType, Prefix, ProtoVersion, ProtocolError, Seq, Welcome, decode_plain,
    encode_frame,
};
use crate::server::sequencer::{DetachCause, WatermarkReport, encode_control};
use crate::server::{Epoch, HelloRequest, Metrics, Outbox, Sequencer, ServeConfig};
use crate::testkit::clock::{TestClock, Timeouts};
use crate::testkit::faults::{FaultScript, FaultyTransport};
use crate::testkit::memnet::{HubConfig, HubStats, InMemoryHub};
use crate::transport::{
    AcceptedConn, BodyStream, DialOptions, Endpoint, MpscBody, MpscSender, PeerId, StreamKind,
    Transport, TransportError,
};

/// 一次 harness 启动所需的全部输入。
#[derive(Debug, Clone)]
pub struct ClusterSpec {
    /// 服务器 epoch 与客户端 id 的确定性种子。
    pub seed: u64,
    /// 启动时连接的客户端。
    pub clients: Vec<ClientSpec>,
    /// 内存网络参数。
    pub network: HubConfig,
    /// 测试超时集合。
    pub timeouts: Timeouts,
}

impl ClusterSpec {
    /// 空集群；用 [`ClusterSpec::with_client`] 追加客户端。
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            clients: Vec::new(),
            network: HubConfig::default(),
            timeouts: Timeouts::for_tests(),
        }
    }

    /// 追加一个客户端。
    pub fn with_client(mut self, client: ClientSpec) -> Self {
        self.clients.push(client);
        self
    }

    /// 替换内存网络参数。
    pub fn with_network(mut self, network: HubConfig) -> Self {
        self.network = network;
        self
    }
}

/// 一个客户端的身份与故障脚本。
#[derive(Debug, Clone)]
pub struct ClientSpec {
    /// 测试内唯一名字。
    pub name: String,
    /// 固定 client id；`None` 时由 seed 与序号派生。
    pub client_id: Option<ClientId>,
    /// 可选的帧级故障脚本。
    pub fault: Option<FaultScript>,
}

impl ClientSpec {
    /// 以名字创建；id 自动派生。
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            client_id: None,
            fault: None,
        }
    }

    /// 固定 client id（双开、漫游、踢旧留新用例）。
    pub fn with_client_id(mut self, client_id: ClientId) -> Self {
        self.client_id = Some(client_id);
        self
    }

    /// 给这个客户端的两个方向都套上故障脚本。
    pub fn with_fault(mut self, script: FaultScript) -> Self {
        self.fault = Some(script);
        self
    }
}

/// harness 错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClusterError {
    /// 字节传输失败。
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    /// 帧编解码失败。
    #[error("protocol: {0}")]
    Protocol(#[from] ProtocolError),
    /// WCP 消息失败。
    #[error("message: {0}")]
    Message(#[from] MessageError),
    /// 等待超过期限。
    #[error("timeout waiting for {0}")]
    Timeout(&'static str),
    /// 客户端名字不存在。
    #[error("unknown client {0}")]
    UnknownClient(String),
    /// 客户端名字重复。
    #[error("duplicate client name {0}")]
    DuplicateClient(String),
    /// 握手没有拿到合法 WELCOME。
    #[error("handshake: {0}")]
    Handshake(String),
    /// 服务器 actor 失败。
    #[error("server: {0}")]
    Server(String),
}

/// 客户端生命周期，只描述连接，不描述同步相位。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    /// 已收到 WELCOME，可收发帧。
    Online,
    /// 被踢或连接关闭。
    Closed,
    /// 内存网络被切断。
    Partitioned,
}

/// 一个已连接的客户端。
///
/// `Clone` 共享同一个 uplink 与下行接收队列；测试可以在持有
/// [`Cluster`] 的同时保存句柄。
#[derive(Clone)]
pub struct ClientHandle {
    name: String,
    id: ClientId,
    peer: PeerId,
    epoch: Arc<AtomicU64>,
    applied: Arc<AtomicU64>,
    rpc: Arc<Mutex<Box<dyn Transport>>>,
    events: Arc<Mutex<mpsc::Receiver<FrameBuf>>>,
    state: Arc<Mutex<ClientState>>,
}

impl std::fmt::Debug for ClientHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientHandle")
            .field("name", &self.name)
            .field("id", &self.id)
            .field("peer", &self.peer)
            .field("epoch", &self.epoch())
            .field("applied_seq", &self.applied_seq())
            .finish_non_exhaustive()
    }
}

impl ClientHandle {
    /// 测试内名字。
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 客户端身份。
    pub const fn id(&self) -> ClientId {
        self.id
    }

    /// 内存网络句柄；`partition`/`heal` 使用。
    pub const fn peer(&self) -> PeerId {
        self.peer
    }

    /// WELCOME 中的服务器 epoch。
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// 已应用的最高 seq；ORDERED 到达时更新。
    pub fn applied_seq(&self) -> Seq {
        Seq(self.applied.load(Ordering::SeqCst))
    }

    /// 连接状态。
    pub async fn state(&self) -> ClientState {
        *self.state.lock().await
    }

    /// 发送一个已构造的帧。
    pub async fn send_frame(&self, frame: &FrameBuf) -> Result<(), ClusterError> {
        let bytes = encode_frame(&FrameRef::new(&frame.header, &frame.prefix, &frame.body))?;
        self.rpc.lock().await.send(Bytes::from(bytes)).await?;
        Ok(())
    }

    /// 发送一个 `ORDERED` 帧。body 对服务器不透明，测试可用任意 ≥30 B 的
    /// 载荷；需要真实 AEAD 的用例用 F 层或 `client::net` 的编码器。
    pub async fn send_ordered(&self, body: Vec<u8>) -> Result<(), ClusterError> {
        if body.len() < crate::protocol::ENV_OVERHEAD as usize {
            return Err(ClusterError::Handshake(format!(
                "ORDERED body is {} B, sealed minimum is {} B",
                body.len(),
                crate::protocol::ENV_OVERHEAD
            )));
        }
        let mut header = FrameHeader::new(
            MsgType::ORDERED,
            crate::protocol::Flags::ENC,
            0,
            Seq::UNSEQUENCED,
        );
        header.len = u32::try_from(body.len())
            .map_err(|_| ClusterError::Handshake("body too large".to_owned()))?;
        let frame = FrameBuf::new(header, Prefix::None, body);
        self.send_frame(&frame).await
    }

    /// 读取下一个下行帧；超时返回 `Ok(None)`。
    pub async fn recv(&self, timeout: Duration) -> Result<Option<FrameBuf>, ClusterError> {
        let mut events = self.events.lock().await;
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Some(frame)) => Ok(Some(frame)),
            Ok(None) => Ok(None),
            Err(_) => Ok(None),
        }
    }

    /// 读取直到指定类型；其他类型被丢弃。
    pub async fn recv_type(
        &self,
        msg_type: MsgType,
        timeout: Duration,
    ) -> Result<Option<FrameBuf>, ClusterError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            match self.recv(remaining).await? {
                Some(frame) if frame.header.msg_type == msg_type => return Ok(Some(frame)),
                Some(_) => continue,
                None => return Ok(None),
            }
        }
    }

    /// 关闭 uplink；服务端随后 detach，下行自然结束。
    pub async fn close(&self) -> Result<(), ClusterError> {
        self.rpc.lock().await.close().await?;
        *self.state.lock().await = ClientState::Closed;
        Ok(())
    }
}

/// 一次 `quiesce` 的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuiesceReport {
    /// 服务器当前 seq。
    pub server_seq: Seq,
    /// 每个客户端已应用的 seq。
    pub clients: BTreeMap<String, Seq>,
    /// 从调用到稳定的实际时间。
    pub elapsed: Duration,
}

/// 集群级统计快照。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterStats {
    /// 服务器 epoch。
    pub epoch: u64,
    /// 服务器当前 seq。
    pub server_seq: Seq,
    /// 已连接客户端数。
    pub clients: usize,
    /// 内存网络统计。
    pub hub: HubStats,
}

/// 进程内多客户端集群。
pub struct Cluster {
    hub: Arc<InMemoryHub>,
    server: ServerNode,
    clients: BTreeMap<String, ClientHandle>,
    specs: BTreeMap<String, ClientSpec>,
    clock: Arc<TestClock>,
    timeouts: Timeouts,
    next_client: u64,
}

impl std::fmt::Debug for Cluster {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Cluster")
            .field("epoch", &self.server.epoch)
            .field("server_seq", &self.server.current_seq())
            .field("clients", &self.clients.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Cluster {
    /// 启动服务器并连接 `spec.clients`。
    pub async fn boot(spec: ClusterSpec) -> Result<Self, ClusterError> {
        let hub = InMemoryHub::new(spec.network);
        let server = ServerNode::start(Arc::clone(&hub), spec.seed).await;
        let mut cluster = Self {
            hub,
            server,
            clients: BTreeMap::new(),
            specs: BTreeMap::new(),
            clock: TestClock::new(0),
            timeouts: spec.timeouts,
            next_client: 0,
        };
        for client in spec.clients {
            cluster.add_client(client).await?;
        }
        Ok(cluster)
    }

    /// 连接一个新客户端。
    pub async fn add_client(&mut self, spec: ClientSpec) -> Result<ClientHandle, ClusterError> {
        if self.clients.contains_key(&spec.name) {
            return Err(ClusterError::DuplicateClient(spec.name));
        }
        let index = self.next_client;
        self.next_client += 1;
        let handle = connect(
            &self.hub,
            &spec,
            index,
            self.timeouts.join.max(Duration::from_secs(1)),
        )
        .await?;
        self.clients.insert(spec.name.clone(), handle.clone());
        self.specs.insert(spec.name.clone(), spec);
        Ok(handle)
    }

    /// 断开并移除一个客户端。
    pub async fn remove_client(&mut self, name: &str) -> Result<(), ClusterError> {
        let handle = self
            .clients
            .remove(name)
            .ok_or_else(|| ClusterError::UnknownClient(name.to_owned()))?;
        let _ = handle.close().await;
        self.hub.partition(handle.peer);
        Ok(())
    }

    /// 切断一个客户端的全部连接；旧连接不复活。
    pub async fn partition(&mut self, name: &str) -> Result<(), ClusterError> {
        let handle = self
            .clients
            .get(name)
            .ok_or_else(|| ClusterError::UnknownClient(name.to_owned()))?;
        self.hub.partition(handle.peer);
        *handle.state.lock().await = ClientState::Partitioned;
        Ok(())
    }

    /// 恢复可拨号性；不重连旧连接。
    pub async fn heal(&mut self, name: &str) -> Result<(), ClusterError> {
        let handle = self
            .clients
            .get(name)
            .ok_or_else(|| ClusterError::UnknownClient(name.to_owned()))?;
        self.hub.heal(handle.peer);
        Ok(())
    }

    /// 用同一 client id、同一名字重新建连；旧会话先关闭。
    pub async fn remount_client(&mut self, name: &str) -> Result<ClientHandle, ClusterError> {
        let spec = self
            .specs
            .get(name)
            .cloned()
            .ok_or_else(|| ClusterError::UnknownClient(name.to_owned()))?;
        if let Some(handle) = self.clients.remove(name) {
            let _ = handle.close().await;
            self.hub.partition(handle.peer);
        }
        let index = self.next_client;
        self.next_client += 1;
        let handle = connect(
            &self.hub,
            &spec,
            index,
            self.timeouts.join.max(Duration::from_secs(1)),
        )
        .await?;
        self.clients.insert(spec.name.clone(), handle.clone());
        Ok(handle)
    }

    /// 用新 epoch 重启服务器：关闭所有会话、seq 归零、旧 epoch 不再可用。
    pub async fn restart_server(&mut self, new_epoch: u64) -> Result<(), ClusterError> {
        let handles: Vec<ClientHandle> = self.clients.values().cloned().collect();
        for handle in handles {
            let _ = handle.close().await;
            self.hub.partition(handle.peer);
        }
        self.clients.clear();
        self.server.shutdown_in_place().await;
        self.server = ServerNode::start(Arc::clone(&self.hub), new_epoch).await;
        Ok(())
    }

    /// 等待所有在线客户端追平服务器 seq。
    ///
    /// 条件与 45 §3.6 一致：客户端已应用 seq 等于服务器当前 seq，且服务器
    /// seq 在观察窗口内不再变化。没有固定 sleep。
    pub async fn quiesce(&mut self, deadline: Duration) -> Result<QuiesceReport, ClusterError> {
        let started = Instant::now();
        let mut previous: Option<(Seq, BTreeMap<String, Seq>)> = None;
        let mut stable_polls = 0_u8;
        loop {
            let target = self.server.current_seq();
            let clients: BTreeMap<String, Seq> = self
                .clients
                .iter()
                .map(|(name, handle)| (name.clone(), handle.applied_seq()))
                .collect();
            let all_caught_up = clients.values().all(|applied| *applied >= target);
            let unchanged = previous.as_ref() == Some(&(target, clients.clone()));
            if all_caught_up && self.server.current_seq() == target && unchanged {
                stable_polls = stable_polls.saturating_add(1);
                if stable_polls >= 2 {
                    return Ok(QuiesceReport {
                        server_seq: target,
                        clients,
                        elapsed: started.elapsed(),
                    });
                }
            } else {
                stable_polls = 0;
            }
            previous = Some((target, clients));
            if started.elapsed() >= deadline {
                return Err(ClusterError::Timeout("quiesce"));
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// 按名字取客户端。
    pub fn client(&self, name: &str) -> Option<&ClientHandle> {
        self.clients.get(name)
    }

    /// 全部客户端。
    pub fn clients(&self) -> impl Iterator<Item = &ClientHandle> {
        self.clients.values()
    }

    /// 服务器当前 seq。
    pub fn server_seq(&self) -> Seq {
        self.server.current_seq()
    }

    /// 服务器 epoch。
    pub const fn epoch(&self) -> u64 {
        self.server.epoch
    }

    /// 暂停时钟；只用于 mtime/审计时间，不参与排序。
    pub fn clock(&self) -> &Arc<TestClock> {
        &self.clock
    }

    /// 内存网络统计。
    pub fn hub_stats(&self) -> HubStats {
        self.hub.stats()
    }

    /// 集群统计快照。
    pub fn stats(&self) -> ClusterStats {
        ClusterStats {
            epoch: self.server.epoch,
            server_seq: self.server.current_seq(),
            clients: self.clients.len(),
            hub: self.hub.stats(),
        }
    }

    /// 驱动一次服务器维护 tick（水位线/健康检查）。
    ///
    /// 内存 harness 不自动起 ticker，需要 T1/T3/T5 语义的测试显式推进。
    pub async fn tick(&self) -> Result<(), ClusterError> {
        self.server
            .sequencer
            .tick(Instant::now())
            .await
            .map_err(|error| ClusterError::Server(error.to_string()))
    }

    /// 服务器诊断快照。
    pub async fn server_snapshot(&self) -> Result<crate::server::SeqSnapshot, ClusterError> {
        self.server
            .sequencer
            .snapshot()
            .await
            .map_err(|error| ClusterError::Server(error.to_string()))
    }
}

struct ServerNode {
    sequencer: Sequencer,
    epoch: u64,
    accept: JoinHandle<()>,
    actor: Option<JoinHandle<()>>,
}

impl ServerNode {
    async fn start(hub: Arc<InMemoryHub>, epoch_raw: u64) -> Self {
        let config = Arc::new(ServeConfig::for_tests());
        let epoch = Epoch::new(epoch_raw);
        let metrics = Arc::new(Metrics::new(epoch));
        let (sequencer, actor) = Sequencer::start(Arc::clone(&config), epoch, metrics);
        let acceptor = hub.acceptor();
        let accept_hub = Arc::clone(&hub);
        let accept_config = Arc::clone(&config);
        let accept_sequencer = sequencer.clone();
        let accept = tokio::spawn(async move {
            loop {
                match acceptor.accept().await {
                    Ok(conn) => spawn_session(
                        Arc::clone(&accept_hub),
                        Arc::clone(&accept_config),
                        accept_sequencer.clone(),
                        conn,
                    ),
                    Err(TransportError::Closed) => break,
                    Err(_) => continue,
                }
            }
        });
        Self {
            sequencer,
            epoch: epoch_raw,
            accept,
            actor: Some(actor),
        }
    }

    fn current_seq(&self) -> Seq {
        self.sequencer.current_seq()
    }

    async fn shutdown_in_place(&mut self) {
        self.accept.abort();
        let _ = self.sequencer.shutdown().await;
        if let Some(actor) = self.actor.take() {
            actor.abort();
            let _ = actor.await;
        }
    }
}

fn spawn_session(
    hub: Arc<InMemoryHub>,
    config: Arc<ServeConfig>,
    sequencer: Sequencer,
    conn: AcceptedConn,
) {
    match conn.kind {
        StreamKind::Rpc => {
            tokio::spawn(run_rpc(hub, config, sequencer, conn));
        }
        StreamKind::Events => {
            tokio::spawn(run_events(sequencer, conn));
        }
    }
}

async fn run_events(sequencer: Sequencer, conn: AcceptedConn) {
    let nonce = conn.nonce;
    let mut transport = conn.transport;
    let (out, body) = MpscBody::channel(64);
    if sequencer.events(nonce, out).await.is_err() {
        return;
    }
    let mut body = BodyStream::new(body);
    while let Ok(Some(bytes)) = body.next_bytes().await {
        if transport.send(bytes).await.is_err() {
            break;
        }
    }
    let _ = transport.close().await;
}

async fn run_rpc(
    _hub: Arc<InMemoryHub>,
    config: Arc<ServeConfig>,
    sequencer: Sequencer,
    conn: AcceptedConn,
) {
    let peer = conn.peer;
    let nonce = conn.nonce;
    let claimed = conn.client_id;
    let mut transport = conn.transport;
    let mut decoder = FrameDecoder::new(config.limits);
    let mut client: Option<ClientId> = None;
    let mut generation = 0_u64;

    'outer: loop {
        let chunk = match transport.recv().await {
            Ok(Some(chunk)) => chunk,
            _ => break,
        };
        if decoder.push(&chunk).is_err() {
            break;
        }
        loop {
            match decoder.next_frame_owned() {
                Ok(Some(frame)) => {
                    if let Some(id) = client {
                        if handle_frame(&sequencer, id, frame).await.is_err() {
                            break 'outer;
                        }
                    } else {
                        match start_session(&sequencer, &config, peer, nonce, claimed, frame).await
                        {
                            Ok((id, assigned)) => {
                                client = Some(id);
                                generation = assigned;
                            }
                            Err(_) => break 'outer,
                        }
                    }
                }
                Ok(None) => break,
                Err(_) => break 'outer,
            }
        }
    }

    if let Some(id) = client {
        let _ = sequencer
            .detach(id, generation, DetachCause::Disconnected)
            .await;
    }
    let _ = transport.close().await;
}

async fn start_session(
    sequencer: &Sequencer,
    config: &Arc<ServeConfig>,
    peer: PeerId,
    nonce: u64,
    claimed: Option<[u8; 16]>,
    frame: FrameBuf,
) -> Result<(ClientId, u64), ClusterError> {
    if frame.header.msg_type != MsgType::HELLO {
        return Err(ClusterError::Handshake(format!(
            "first frame is {}, not HELLO",
            frame.header.msg_type.name()
        )));
    }
    let ctrl = frame
        .prefix
        .as_ctrl()
        .copied()
        .ok_or_else(|| ClusterError::Handshake("HELLO without control prefix".to_owned()))?;
    let Message::Hello(hello) = decode_plain(MsgType::HELLO, &frame.body, &config.limits)? else {
        return Err(ClusterError::Handshake("bad HELLO body".to_owned()));
    };
    if let Some(claimed) = claimed {
        if ClientId::from_bytes(claimed) != hello.client_id {
            return Err(ClusterError::Handshake(
                "declared client id disagrees with HELLO".to_owned(),
            ));
        }
    }

    let (outbox, data, ctrl_rx) = Outbox::new(&config.outbox);
    let request = HelloRequest {
        nonce,
        client_id: hello.client_id,
        epoch_seen: ctrl.epoch_seen,
        applied_seq: ctrl.applied_seq,
        peer,
        outbox,
        data,
        ctrl: ctrl_rx,
    };
    let mut reply = sequencer
        .hello(request)
        .await
        .map_err(|reason| ClusterError::Server(format!("HELLO rejected: {reason:?}")))?;
    let generation = reply.generation;
    let events = match reply.events.take() {
        Some(events) => events,
        None => {
            let wait = reply
                .wait
                .take()
                .ok_or_else(|| ClusterError::Handshake("no downlink waiter".to_owned()))?;
            match tokio::time::timeout(config.hello_timeout, wait).await {
                Ok(Ok(events)) => events,
                _ => {
                    let _ = sequencer
                        .detach(hello.client_id, generation, DetachCause::Disconnected)
                        .await;
                    return Err(ClusterError::Timeout("downlink pairing"));
                }
            }
        }
    };
    tokio::spawn(run_writer(events, reply.data, reply.ctrl));
    Ok((reply.client_id, generation))
}

async fn handle_frame(
    sequencer: &Sequencer,
    client: ClientId,
    frame: FrameBuf,
) -> Result<(), ClusterError> {
    match frame.header.msg_type {
        MsgType::ORDERED => sequencer
            .ordered(client, frame)
            .await
            .map_err(|error| ClusterError::Server(error.to_string())),
        MsgType::RELAY | MsgType::FLOW | MsgType::SYNC_END | MsgType::STREAM_DATA => sequencer
            .relay(client, frame)
            .await
            .map_err(|error| ClusterError::Server(error.to_string())),
        MsgType::PING => {
            let Some(ctrl) = frame.prefix.as_ctrl().copied() else {
                return Ok(());
            };
            sequencer
                .watermark(WatermarkReport {
                    client,
                    applied_seq: ctrl.applied_seq,
                    epoch_seen: ctrl.epoch_seen,
                    rtt_ms: None,
                    at: Instant::now(),
                })
                .await
                .map_err(|error| ClusterError::Server(error.to_string()))
        }
        MsgType::LEAVE => sequencer
            .leave(client, Some(frame))
            .await
            .map_err(|error| ClusterError::Server(error.to_string())),
        _ => Ok(()),
    }
}

async fn run_writer(
    out: MpscSender,
    mut data: mpsc::Receiver<Bytes>,
    mut ctrl: mpsc::Receiver<Bytes>,
) {
    let mut deferred_kick: Option<Bytes> = None;
    loop {
        tokio::select! {
            biased;
            Some(frame) = ctrl.recv(), if deferred_kick.is_none() => {
                if is_kick(&frame) {
                    deferred_kick = Some(frame);
                    continue;
                }
                if out.send(frame).await.is_err() {
                    break;
                }
            }
            Some(frame) = data.recv() => {
                if out.send(frame).await.is_err() {
                    break;
                }
            }
            else => break,
        }
    }
    if let Some(kick) = deferred_kick {
        let _ = out.send(kick).await;
    }
}

fn is_kick(frame: &Bytes) -> bool {
    frame.len() >= crate::protocol::HEADER_LEN
        && frame[0] == crate::protocol::MAGIC
        && frame[2] == MsgType::KICK.get()
}

async fn connect(
    hub: &Arc<InMemoryHub>,
    spec: &ClientSpec,
    index: u64,
    timeout: Duration,
) -> Result<ClientHandle, ClusterError> {
    let id = spec
        .client_id
        .unwrap_or_else(|| ClientId::from_bytes(derived_id(index)));
    let nonce = rand::random::<u64>();
    let endpoint = Endpoint::parse("http://127.0.0.1:1/ns").map_err(TransportError::from)?;
    let options = DialOptions::new(nonce).with_client_id(id.to_bytes());
    let rpc = hub
        .dialer()
        .dial(&endpoint, StreamKind::Rpc, &options)
        .await?;
    let events = hub
        .dialer()
        .dial(&endpoint, StreamKind::Events, &options)
        .await?;
    let rpc: Box<dyn Transport> = match &spec.fault {
        Some(script) => Box::new(FaultyTransport::wrap(rpc, script.clone())),
        None => rpc,
    };
    let events: Box<dyn Transport> = match &spec.fault {
        Some(script) => Box::new(FaultyTransport::wrap(events, script.clone())),
        None => events,
    };
    let peer = PeerId::from_serial(nonce);

    let hello = Hello::new(ProtoVersion::CURRENT, Caps::REQUIRED, id, [0x5a; 32]);
    let body = hello.encode()?;
    let hello_frame = encode_control(
        MsgType::HELLO,
        Prefix::Ctrl(CtrlPrefix::new(Seq::UNSEQUENCED, 0)),
        &body,
        Seq::UNSEQUENCED,
    )?;
    let mut rpc = rpc;
    rpc.send(hello_frame).await?;

    let mut events = events;
    let mut decoder = FrameDecoder::new(Limits::default());
    let deadline = tokio::time::Instant::now() + timeout;
    let welcome: Welcome = loop {
        if let Some(frame) = decoder.next_frame_owned()? {
            if frame.header.msg_type == MsgType::WELCOME {
                match decode_plain(MsgType::WELCOME, &frame.body, &Limits::default())? {
                    Message::Welcome(welcome) => break welcome,
                    _ => {
                        return Err(ClusterError::Handshake(
                            "WELCOME body did not decode as WELCOME".to_owned(),
                        ));
                    }
                }
            }
            continue;
        }
        let now = tokio::time::Instant::now();
        let Some(remaining) = deadline.checked_duration_since(now) else {
            return Err(ClusterError::Timeout("WELCOME"));
        };
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Ok(Some(chunk))) => decoder.push(&chunk)?,
            Ok(Ok(None)) => {
                return Err(ClusterError::Handshake("downlink closed".to_owned()));
            }
            Ok(Err(error)) => return Err(ClusterError::Transport(error)),
            Err(_) => return Err(ClusterError::Timeout("WELCOME")),
        }
    };

    finish_handshake(rpc, events, decoder, welcome, id, peer, spec.name.clone()).await
}

async fn finish_handshake(
    rpc: Box<dyn Transport>,
    events: Box<dyn Transport>,
    decoder: FrameDecoder,
    welcome: Welcome,
    id: ClientId,
    peer: PeerId,
    name: String,
) -> Result<ClientHandle, ClusterError> {
    let epoch = Arc::new(AtomicU64::new(welcome.epoch));
    let applied = Arc::new(AtomicU64::new(welcome.current_seq.get()));
    let state = Arc::new(Mutex::new(ClientState::Online));
    let (tx, rx) = mpsc::channel(256);
    tokio::spawn(read_events(
        events,
        decoder,
        tx,
        Arc::clone(&applied),
        Arc::clone(&state),
    ));
    Ok(ClientHandle {
        name,
        id,
        peer,
        epoch,
        applied,
        rpc: Arc::new(Mutex::new(rpc)),
        events: Arc::new(Mutex::new(rx)),
        state,
    })
}

async fn read_events(
    mut events: Box<dyn Transport>,
    mut decoder: FrameDecoder,
    out: mpsc::Sender<FrameBuf>,
    applied: Arc<AtomicU64>,
    state: Arc<Mutex<ClientState>>,
) {
    loop {
        loop {
            match decoder.next_frame_owned() {
                Ok(Some(frame)) => {
                    if frame.header.msg_type == MsgType::ORDERED {
                        applied.fetch_max(frame.header.seq.get(), Ordering::SeqCst);
                    }
                    if frame.header.msg_type == MsgType::KICK {
                        *state.lock().await = ClientState::Closed;
                    }
                    if out.send(frame).await.is_err() {
                        return;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    *state.lock().await = ClientState::Closed;
                    return;
                }
            }
        }
        match events.recv().await {
            Ok(Some(chunk)) => {
                if decoder.push(&chunk).is_err() {
                    *state.lock().await = ClientState::Closed;
                    return;
                }
            }
            _ => {
                *state.lock().await = ClientState::Closed;
                return;
            }
        }
    }
}

fn derived_id(index: u64) -> [u8; 16] {
    let mut raw = [0_u8; 16];
    raw[..8].copy_from_slice(&0x534d_4f50_0000_0000_u64.to_be_bytes());
    raw[8..].copy_from_slice(&index.to_be_bytes());
    raw
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::testkit::faults::{Action as FaultAction, Direction, FaultRule, Selector};

    fn two_clients() -> ClusterSpec {
        ClusterSpec::new(7)
            .with_client(ClientSpec::new("a"))
            .with_client(ClientSpec::new("b"))
    }

    /// W18: two clients connect, one ORDERED reaches both, seq is contiguous.
    #[tokio::test]
    async fn u_testkit_cluster_two_clients_broadcast() {
        let mut cluster = Cluster::boot(two_clients()).await.unwrap();
        let a = cluster.client("a").unwrap().clone();
        let b = cluster.client("b").unwrap().clone();

        a.send_ordered(vec![0x11; 32]).await.unwrap();
        let a_frame = a.recv(Duration::from_secs(1)).await.unwrap().unwrap();
        let b_frame = b.recv(Duration::from_secs(1)).await.unwrap().unwrap();
        assert_eq!(a_frame.header.msg_type, MsgType::ORDERED);
        assert_eq!(b_frame.header.msg_type, MsgType::ORDERED);
        assert_eq!(a_frame.header.seq, Seq(1));
        assert_eq!(b_frame.header.seq, Seq(1));

        let report = cluster.quiesce(Duration::from_secs(1)).await.unwrap();
        assert_eq!(report.server_seq, Seq(1));
        assert_eq!(a.applied_seq(), Seq(1));
        assert_eq!(b.applied_seq(), Seq(1));
    }

    /// W18: partition closes the old session; remount resumes with the
    /// server-side sequence, not with a local one.
    #[tokio::test]
    async fn u_testkit_cluster_partition_and_remount() {
        let mut cluster = Cluster::boot(two_clients()).await.unwrap();
        let a = cluster.client("a").unwrap().clone();
        let b = cluster.client("b").unwrap().clone();
        a.send_ordered(vec![0x22; 32]).await.unwrap();
        cluster.quiesce(Duration::from_secs(1)).await.unwrap();

        cluster.partition("a").await.unwrap();
        assert!(
            a.send_ordered(vec![0x23; 32]).await.is_err(),
            "a partitioned uplink must fail"
        );

        cluster.heal("a").await.unwrap();
        let a2 = cluster.remount_client("a").await.unwrap();
        assert!(a2.applied_seq() >= Seq(1));
        let next = Seq(cluster.server_seq().get() + 1);
        b.send_ordered(vec![0x24; 32]).await.unwrap();
        let frame = a2.recv(Duration::from_secs(1)).await.unwrap().unwrap();
        assert_eq!(frame.header.seq, next);
        assert_eq!(a2.applied_seq(), next);
    }

    /// W18: a server restart changes the epoch and resets seq to zero.
    #[tokio::test]
    async fn u_testkit_cluster_restart_epoch() {
        let mut cluster = Cluster::boot(two_clients()).await.unwrap();
        let a = cluster.client("a").unwrap().clone();
        a.send_ordered(vec![0x33; 32]).await.unwrap();
        cluster.quiesce(Duration::from_secs(1)).await.unwrap();

        cluster.restart_server(0x99).await.unwrap();
        assert!(a.send_ordered(vec![0x34; 32]).await.is_err());
        let a2 = cluster.remount_client("a").await.unwrap();
        assert_eq!(a2.epoch(), 0x99);
        assert_eq!(a2.applied_seq(), Seq::UNSEQUENCED);
        a2.send_ordered(vec![0x35; 32]).await.unwrap();
        let frame = a2.recv(Duration::from_secs(1)).await.unwrap().unwrap();
        assert_eq!(frame.header.seq, Seq(1));
        assert_eq!(cluster.epoch(), 0x99);
    }

    /// W18: a dropped uplink frame is not retried and does not advance seq.
    #[tokio::test]
    async fn u_testkit_cluster_fault_drop_is_reproducible() {
        let script = FaultScript::new(0x51a7).with_rule(FaultRule::new(
            Direction::Up,
            Selector::Type(MsgType::ORDERED.get()),
            FaultAction::Drop,
        ));
        let spec = ClusterSpec::new(11).with_client(ClientSpec::new("a").with_fault(script));
        let mut cluster = Cluster::boot(spec).await.unwrap();
        let a = cluster.client("a").unwrap().clone();

        a.send_ordered(vec![0x44; 32]).await.unwrap();
        cluster.quiesce(Duration::from_secs(1)).await.unwrap();
        assert_eq!(cluster.server_seq(), Seq::UNSEQUENCED);
        assert!(a.recv(Duration::from_millis(20)).await.unwrap().is_none());
    }

    /// W18: duplicate client id kicks the old session (T4) and the new one
    /// continues with the same server sequence.
    #[tokio::test]
    async fn u_testkit_cluster_duplicate_client_id() {
        let id = ClientId::from_bytes([0x77; 16]);
        let spec = ClusterSpec::new(13).with_client(ClientSpec::new("first").with_client_id(id));
        let mut cluster = Cluster::boot(spec).await.unwrap();
        let first = cluster.client("first").unwrap().clone();
        first.send_ordered(vec![0x55; 32]).await.unwrap();
        cluster.quiesce(Duration::from_secs(1)).await.unwrap();

        let second = cluster
            .add_client(ClientSpec::new("second").with_client_id(id))
            .await
            .unwrap();
        let kick = first
            .recv_type(MsgType::KICK, Duration::from_secs(1))
            .await
            .unwrap();
        assert!(kick.is_some(), "the old session must receive KICK");
        let next = Seq(cluster.server_seq().get() + 1);
        second.send_ordered(vec![0x56; 32]).await.unwrap();
        let frame = second.recv(Duration::from_secs(1)).await.unwrap().unwrap();
        assert_eq!(frame.header.seq, next);
    }
}
