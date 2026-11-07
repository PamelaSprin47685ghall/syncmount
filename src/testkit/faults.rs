//! 确定性故障注入。
//!
//! 第一波只提供与传输无关的决策引擎：给定 `(dir, type, op_class, seq)` 元数据，
//! 按 [`FaultScript`] 决定丢包、延迟、重复、乱序等动作。`FaultyTransport`
//! 的字节级包装在 transport 契约冻结后接入（第二波），只消费本引擎的
//! [`AppliedFault`]。
//!
//! 随机源是自包含的 SplitMix64：同一 `seed` 与同一帧序列必然产生同一决策序列，
//! 不依赖 `rand`/`rand_chacha` 的版本行为。

use std::collections::VecDeque;
use std::time::Duration;

use bytes::Bytes;

use crate::protocol::{FRAME_MAX, HEADER_LEN};
use crate::transport::{BoxFut, Transport, TransportError};

/// 帧方向。规则用 [`Direction::Both`] 同时匹配两个方向；
/// [`FrameMeta`] 只应携带 `Up` 或 `Down`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Up,
    Down,
    Both,
}

impl Direction {
    /// `self` 是否覆盖实际方向 `actual`。
    pub fn matches(self, actual: Direction) -> bool {
        self == Direction::Both || self == actual
    }

    /// The direction of the opposite half of one stream.
    pub const fn opposite(self) -> Self {
        match self {
            Self::Up => Self::Down,
            Self::Down => Self::Up,
            Self::Both => Self::Both,
        }
    }
}

/// 选择器：决定一条规则作用于哪些帧。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selector {
    /// 所有帧。
    Any,
    /// 消息类型（`u8`；第二波由 `protocol::MessageType` 映射）。
    Type(u8),
    /// op_class 字节。
    OpClass(u8),
    /// 精确 seq。
    Seq(u64),
    /// 闭区间 `[first, last]`。
    SeqRange(u64, u64),
    /// 该规则方向匹配的第 `n` 个候选帧（0-based）。
    Nth(usize),
}

impl Selector {
    /// 选择器是否命中；`nth_seen` 是此规则此前方向匹配的候选帧数（0-based）。
    /// [`Selector::Nth`] 用它选择第 `n` 个候选帧；其他选择器忽略该参数。
    pub fn matches(&self, meta: &FrameMeta, nth_seen: usize) -> bool {
        match *self {
            Selector::Any => true,
            Selector::Type(ty) => meta.ty == ty,
            Selector::OpClass(op_class) => meta.op_class == op_class,
            Selector::Seq(seq) => meta.seq == seq,
            Selector::SeqRange(first, last) => first <= meta.seq && meta.seq <= last,
            Selector::Nth(n) => nth_seen == n,
        }
    }
}

/// 对命中的帧执行的动作。语义由传输层落实；本层只负责确定性选择。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// 丢弃该帧。
    Drop,
    /// 额外复制 `n` 份。
    Duplicate(u8),
    /// 延迟投递。
    Delay(Duration),
    /// 进入 `window` 帧的重排缓冲。
    Reorder(u16),
    /// 翻转 `byte` 处的位（`xor`）。
    Corrupt { byte: usize, xor: u8 },
    /// 截断到 `bytes`。
    Truncate { bytes: usize },
    /// 该帧后关闭连接（EOF）。
    Close,
    /// 静默 `d`，不发 EOF（半开）。
    Blackhole(Duration),
    /// 改写成未知消息类型。
    UnknownType(u8),
    /// 破坏 AEAD tag。
    TamperTag,
}

/// 一条故障规则。
#[derive(Debug, Clone, PartialEq)]
pub struct FaultRule {
    pub dir: Direction,
    pub selector: Selector,
    pub action: Action,
    /// 命中概率，`[0.0, 1.0]`。
    pub probability: f64,
    /// 最多应用次数；`None` 表示不限。
    pub limit: Option<usize>,
}

impl FaultRule {
    /// 默认概率 1.0、无次数限制。
    pub fn new(dir: Direction, selector: Selector, action: Action) -> Self {
        Self {
            dir,
            selector,
            action,
            probability: 1.0,
            limit: None,
        }
    }

    /// 设置命中概率。
    pub fn with_probability(mut self, probability: f64) -> Self {
        self.probability = probability;
        self
    }

    /// 设置最多应用次数。
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }
}

/// 一个 seed 下的完整故障脚本。规则按顺序判定，第一条命中即生效。
#[derive(Debug, Clone, PartialEq)]
pub struct FaultScript {
    pub seed: u64,
    pub rules: Vec<FaultRule>,
}

impl FaultScript {
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            rules: Vec::new(),
        }
    }

    /// 追加一条规则。
    pub fn with_rule(mut self, rule: FaultRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// 校验所有概率。
    pub fn validate(&self) -> Result<(), FaultError> {
        for (rule_index, rule) in self.rules.iter().enumerate() {
            if !rule.probability.is_finite() {
                return Err(FaultError::NonFiniteProbability { rule_index });
            }
            if !(0.0..=1.0).contains(&rule.probability) {
                return Err(FaultError::ProbabilityOutOfRange {
                    rule_index,
                    probability: rule.probability,
                });
            }
        }
        Ok(())
    }
}

/// 脚本校验错误。
#[derive(Debug, Clone, PartialEq)]
pub enum FaultError {
    NonFiniteProbability { rule_index: usize },
    ProbabilityOutOfRange { rule_index: usize, probability: f64 },
}

impl std::fmt::Display for FaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonFiniteProbability { rule_index } => {
                write!(f, "fault rule {rule_index}: probability is not finite")
            }
            Self::ProbabilityOutOfRange {
                rule_index,
                probability,
            } => write!(
                f,
                "fault rule {rule_index}: probability {probability} outside [0.0, 1.0]"
            ),
        }
    }
}

impl std::error::Error for FaultError {}

/// 一帧的可判定元数据。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameMeta {
    pub dir: Direction,
    pub ty: u8,
    pub op_class: u8,
    pub seq: u64,
}

impl FrameMeta {
    pub fn new(dir: Direction, ty: u8, op_class: u8, seq: u64) -> Self {
        Self {
            dir,
            ty,
            op_class,
            seq,
        }
    }
}

/// 实际生效的故障。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedFault {
    pub rule_index: usize,
    pub action: Action,
}

/// 单条规则的判定记录。
#[derive(Debug, Clone, PartialEq)]
pub struct RuleDecision {
    pub rule_index: usize,
    pub matched_direction: bool,
    pub matched_selector: bool,
    pub limit_reached: bool,
    /// 概率掷骰值；只在方向与选择器都命中且未超限时记录。
    pub roll: Option<f64>,
    pub applied: bool,
}

/// 单帧的完整判定记录。
#[derive(Debug, Clone, PartialEq)]
pub struct TraceEntry {
    pub frame_index: u64,
    pub meta: FrameMeta,
    pub decisions: Vec<RuleDecision>,
    pub applied: Option<AppliedFault>,
}

/// 决策轨迹。失败时用同一 seed 重放即可复现。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FaultTrace {
    entries: Vec<TraceEntry>,
}

impl FaultTrace {
    pub fn entries(&self) -> &[TraceEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 实际注入故障的帧。
    pub fn applied(&self) -> impl Iterator<Item = &TraceEntry> {
        self.entries.iter().filter(|entry| entry.applied.is_some())
    }

    pub fn applied_count(&self) -> usize {
        self.applied().count()
    }
}

/// SplitMix64：小而确定的随机源。同 seed 同序列。
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// `[0.0, 1.0)` 均匀分布。
    pub fn next_f64(&mut self) -> f64 {
        const SCALE: f64 = 1.0 / ((1u64 << 53) as f64);
        ((self.next_u64() >> 11) as f64) * SCALE
    }
}

/// 确定性故障决策引擎。
#[derive(Debug)]
pub struct FaultEngine {
    script: FaultScript,
    rng: SplitMix64,
    used: Vec<usize>,
    nth_seen: Vec<usize>,
    trace: FaultTrace,
    frame_index: u64,
}

impl FaultEngine {
    /// 校验失败时 panic；需要可恢复错误用 [`FaultEngine::try_new`]。
    pub fn new(script: FaultScript) -> Self {
        if let Err(err) = script.validate() {
            panic!("invalid fault script: {err}");
        }
        Self::from_validated(script)
    }

    pub fn try_new(script: FaultScript) -> Result<Self, FaultError> {
        script.validate()?;
        Ok(Self::from_validated(script))
    }

    fn from_validated(script: FaultScript) -> Self {
        let rule_count = script.rules.len();
        Self {
            rng: SplitMix64::new(script.seed),
            script,
            used: vec![0; rule_count],
            nth_seen: vec![0; rule_count],
            trace: FaultTrace::default(),
            frame_index: 0,
        }
    }

    pub fn seed(&self) -> u64 {
        self.script.seed
    }

    pub fn rules(&self) -> &[FaultRule] {
        &self.script.rules
    }

    pub fn trace(&self) -> &FaultTrace {
        &self.trace
    }

    /// 判定一帧；返回第一条命中的规则动作。
    pub fn decide(&mut self, meta: FrameMeta) -> Option<AppliedFault> {
        let frame_index = self.frame_index;
        self.frame_index += 1;
        let mut decisions = Vec::with_capacity(self.script.rules.len());
        let mut applied = None;

        for index in 0..self.script.rules.len() {
            let rule = &self.script.rules[index];
            let matched_direction = rule.dir.matches(meta.dir);
            if !matched_direction {
                decisions.push(RuleDecision {
                    rule_index: index,
                    matched_direction: false,
                    matched_selector: false,
                    limit_reached: false,
                    roll: None,
                    applied: false,
                });
                continue;
            }

            let candidate_index = self.nth_seen[index];
            let matched_selector = rule.selector.matches(&meta, candidate_index);
            self.nth_seen[index] += 1;
            if !matched_selector {
                decisions.push(RuleDecision {
                    rule_index: index,
                    matched_direction: true,
                    matched_selector: false,
                    limit_reached: false,
                    roll: None,
                    applied: false,
                });
                continue;
            }
            let limit_reached = rule.limit.is_some_and(|limit| self.used[index] >= limit);
            if limit_reached {
                decisions.push(RuleDecision {
                    rule_index: index,
                    matched_direction: true,
                    matched_selector: true,
                    limit_reached: true,
                    roll: None,
                    applied: false,
                });
                continue;
            }

            let roll = self.rng.next_f64();
            if roll < rule.probability {
                self.used[index] += 1;
                let fault = AppliedFault {
                    rule_index: index,
                    action: rule.action.clone(),
                };
                decisions.push(RuleDecision {
                    rule_index: index,
                    matched_direction: true,
                    matched_selector: true,
                    limit_reached: false,
                    roll: Some(roll),
                    applied: true,
                });
                applied = Some(fault);
                break;
            }

            decisions.push(RuleDecision {
                rule_index: index,
                matched_direction: true,
                matched_selector: true,
                limit_reached: false,
                roll: Some(roll),
                applied: false,
            });
        }

        self.trace.entries.push(TraceEntry {
            frame_index,
            meta,
            decisions,
            applied: applied.clone(),
        });
        applied
    }

    /// 对一串帧逐条判定。
    pub fn decide_all(
        &mut self,
        metas: impl IntoIterator<Item = FrameMeta>,
    ) -> Vec<Option<AppliedFault>> {
        metas.into_iter().map(|meta| self.decide(meta)).collect()
    }
}

/// One frame after the fault engine has rewritten it.
struct Processed {
    frames: Vec<Bytes>,
    close: bool,
    blackhole: Option<Duration>,
}

impl Processed {
    fn keep(frame: Bytes) -> Self {
        Self {
            frames: vec![frame],
            close: false,
            blackhole: None,
        }
    }

    fn drop_frame() -> Self {
        Self {
            frames: Vec::new(),
            close: false,
            blackhole: None,
        }
    }
}

/// A byte-stream transport that applies a [`FaultScript`] to whole frames.
///
/// The wrapped [`Transport`] carries an arbitrary byte stream; this wrapper
/// re-segments it at the 21-byte frame header, decides once per frame, then
/// re-emits the resulting bytes. Chunk boundaries therefore change, which is
/// legal: [`Transport`] promises bytes, not frames.
///
/// `send` uses `send_dir`; `recv` uses `recv_dir`. The default
/// [`FaultyTransport::wrap`] is the client view: `send` is `Up`, `recv` is
/// `Down`. Use [`FaultyTransport::with_directions`] for a server-side half.
///
/// Determinism: the same seed and the same byte/frame sequence produce the
/// same decisions, the same output bytes and the same [`FaultTrace`]. Delay
/// uses `tokio::time`, so a paused-time test advances instantly.
pub struct FaultyTransport {
    inner: Box<dyn Transport>,
    engine: FaultEngine,
    send_dir: Direction,
    recv_dir: Direction,
    send_buf: Vec<u8>,
    recv_buf: Vec<u8>,
    ready_send: VecDeque<Bytes>,
    ready_recv: VecDeque<Bytes>,
    reorder_send: VecDeque<Bytes>,
    reorder_recv: VecDeque<Bytes>,
    window_send: usize,
    window_recv: usize,
    shuffle: SplitMix64,
    blackhole_until: Option<tokio::time::Instant>,
    closed: bool,
    frames_sent: u64,
    frames_recv: u64,
}

impl std::fmt::Debug for FaultyTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FaultyTransport")
            .field("seed", &self.seed())
            .field("send_dir", &self.send_dir)
            .field("recv_dir", &self.recv_dir)
            .field("frames_sent", &self.frames_sent)
            .field("frames_recv", &self.frames_recv)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl FaultyTransport {
    /// Wrap a client-side transport: `send` is `Up`, `recv` is `Down`.
    pub fn wrap(inner: Box<dyn Transport>, script: FaultScript) -> Self {
        Self::with_directions(inner, script, Direction::Up, Direction::Down)
    }

    /// Wrap any transport with explicit send/receive directions.
    ///
    /// Panics if the script is invalid; use [`FaultyTransport::try_wrap`]
    /// when the script comes from untrusted input.
    pub fn with_directions(
        inner: Box<dyn Transport>,
        script: FaultScript,
        send_dir: Direction,
        recv_dir: Direction,
    ) -> Self {
        let seed = script.seed;
        Self {
            inner,
            engine: FaultEngine::new(script),
            send_dir,
            recv_dir,
            send_buf: Vec::new(),
            recv_buf: Vec::new(),
            ready_send: VecDeque::new(),
            ready_recv: VecDeque::new(),
            reorder_send: VecDeque::new(),
            reorder_recv: VecDeque::new(),
            window_send: 0,
            window_recv: 0,
            shuffle: SplitMix64::new(seed ^ 0x5eed_5eed_5eed_5eed),
            blackhole_until: None,
            closed: false,
            frames_sent: 0,
            frames_recv: 0,
        }
    }

    /// Fallible constructor; see [`FaultEngine::try_new`].
    pub fn try_wrap(inner: Box<dyn Transport>, script: FaultScript) -> Result<Self, FaultError> {
        script.validate()?;
        Ok(Self::wrap(inner, script))
    }

    /// Decision trace, one entry per complete frame.
    pub fn trace(&self) -> &FaultTrace {
        self.engine.trace()
    }

    /// Number of faults actually applied.
    pub fn applied_count(&self) -> usize {
        self.engine.trace().applied_count()
    }

    /// Complete frames handed to `send`.
    pub const fn frames_sent(&self) -> u64 {
        self.frames_sent
    }

    /// Complete frames yielded by `recv`.
    pub const fn frames_recv(&self) -> u64 {
        self.frames_recv
    }

    /// Seed of the wrapped script.
    pub fn seed(&self) -> u64 {
        self.engine.seed()
    }

    /// Whether a `Close` fault or an explicit [`Transport::close`] ended it.
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    async fn process(&mut self, dir: Direction, frame: Bytes) -> Processed {
        if self.is_blackholed() {
            return Processed::drop_frame();
        }
        let (queue, window) = match dir {
            Direction::Down => (&mut self.reorder_recv, self.window_recv),
            _ => (&mut self.reorder_send, self.window_send),
        };
        if !queue.is_empty() && queue.len() < window {
            queue.push_back(frame);
            if queue.len() < window {
                return Processed::drop_frame();
            }
            return self.flush(dir);
        }

        let meta = frame_meta(dir, &frame);
        let Some(AppliedFault { action, .. }) = self.engine.decide(meta) else {
            return Processed::keep(frame);
        };
        match action {
            Action::Drop => Processed::drop_frame(),
            Action::Duplicate(copies) => Processed {
                frames: std::iter::repeat_n(frame, usize::from(copies) + 1).collect(),
                close: false,
                blackhole: None,
            },
            Action::Delay(delay) => {
                tokio::time::sleep(delay).await;
                Processed::keep(frame)
            }
            Action::Reorder(requested) => {
                let requested = usize::from(requested).max(2);
                match dir {
                    Direction::Down => {
                        self.window_recv = requested;
                        self.reorder_recv.push_back(frame);
                    }
                    _ => {
                        self.window_send = requested;
                        self.reorder_send.push_back(frame);
                    }
                }
                let queued = match dir {
                    Direction::Down => self.reorder_recv.len(),
                    _ => self.reorder_send.len(),
                };
                if queued >= requested {
                    self.flush(dir)
                } else {
                    Processed::drop_frame()
                }
            }
            Action::Corrupt { byte, xor } => {
                let mut bytes = frame.to_vec();
                if !bytes.is_empty() {
                    let at = byte % bytes.len();
                    bytes[at] ^= xor;
                }
                Processed::keep(Bytes::from(bytes))
            }
            Action::Truncate { bytes } => {
                let mut wire = frame.to_vec();
                wire.truncate(bytes.min(wire.len()));
                Processed::keep(Bytes::from(wire))
            }
            Action::Close => Processed {
                frames: vec![frame],
                close: true,
                blackhole: None,
            },
            Action::Blackhole(duration) => Processed {
                frames: Vec::new(),
                close: false,
                blackhole: Some(duration),
            },
            Action::UnknownType(raw) => {
                let mut bytes = frame.to_vec();
                if bytes.len() > 2 {
                    bytes[2] = raw;
                }
                Processed::keep(Bytes::from(bytes))
            }
            Action::TamperTag => {
                let mut bytes = frame.to_vec();
                if let Some(last) = bytes.last_mut() {
                    *last ^= 0xff;
                }
                Processed::keep(Bytes::from(bytes))
            }
        }
    }

    fn flush(&mut self, dir: Direction) -> Processed {
        let queue = match dir {
            Direction::Down => &mut self.reorder_recv,
            _ => &mut self.reorder_send,
        };
        let mut frames: Vec<Bytes> = queue.drain(..).collect();
        // Fisher-Yates with the wrapper's own deterministic stream: the
        // engine's RNG must stay reserved for decisions.
        for index in (1..frames.len()).rev() {
            let pick = (self.shuffle.next_u64() % (index as u64 + 1)) as usize;
            frames.swap(index, pick);
        }
        match dir {
            Direction::Down => self.window_recv = 0,
            _ => self.window_send = 0,
        }
        Processed {
            frames,
            close: false,
            blackhole: None,
        }
    }

    fn is_blackholed(&mut self) -> bool {
        let Some(until) = self.blackhole_until else {
            return false;
        };
        if tokio::time::Instant::now() < until {
            return true;
        }
        self.blackhole_until = None;
        false
    }

    async fn pump_send(&mut self) -> Result<(), TransportError> {
        while let Some(frame) = self.ready_send.pop_front() {
            self.inner.send(frame).await?;
            self.frames_sent += 1;
        }
        Ok(())
    }
}

impl Transport for FaultyTransport {
    fn send(&mut self, chunk: Bytes) -> BoxFut<'_, Result<(), TransportError>> {
        Box::pin(async move {
            if self.closed {
                return Err(TransportError::Disconnected);
            }
            self.send_buf.extend_from_slice(&chunk);
            let frames = take_frames(&mut self.send_buf);
            for frame in frames {
                let processed = self.process(self.send_dir, frame).await;
                self.ready_send.extend(processed.frames);
                if let Some(duration) = processed.blackhole {
                    self.blackhole_until = Some(tokio::time::Instant::now() + duration);
                }
                if processed.close {
                    self.pump_send().await?;
                    self.inner.close().await?;
                    self.closed = true;
                    return Ok(());
                }
            }
            self.pump_send().await
        })
    }

    fn recv(&mut self) -> BoxFut<'_, Result<Option<Bytes>, TransportError>> {
        Box::pin(async move {
            loop {
                if let Some(frame) = self.ready_recv.pop_front() {
                    self.frames_recv += 1;
                    return Ok(Some(frame));
                }
                if self.closed {
                    return Ok(None);
                }
                if let Some(until) = self.blackhole_until {
                    let now = tokio::time::Instant::now();
                    if now < until {
                        tokio::time::sleep(until - now).await;
                    }
                    self.blackhole_until = None;
                    continue;
                }
                match self.inner.recv().await? {
                    Some(chunk) => {
                        self.recv_buf.extend_from_slice(&chunk);
                        let frames = take_frames(&mut self.recv_buf);
                        for frame in frames {
                            let processed = self.process(self.recv_dir, frame).await;
                            self.ready_recv.extend(processed.frames);
                            if let Some(duration) = processed.blackhole {
                                self.blackhole_until = Some(tokio::time::Instant::now() + duration);
                            }
                            if processed.close {
                                self.closed = true;
                                self.inner.close().await?;
                            }
                        }
                        if !self.ready_recv.is_empty() {
                            continue;
                        }
                    }
                    None => {
                        if !self.reorder_recv.is_empty() {
                            let flushed = self.flush(self.recv_dir);
                            self.ready_recv.extend(flushed.frames);
                            continue;
                        }
                        if !self.recv_buf.is_empty() {
                            // A half-written trailing frame is returned as-is;
                            // the frame decoder above us will report it.
                            let tail = std::mem::take(&mut self.recv_buf);
                            self.frames_recv += 1;
                            return Ok(Some(Bytes::from(tail)));
                        }
                        self.closed = true;
                        return Ok(None);
                    }
                }
            }
        })
    }

    fn close(&mut self) -> BoxFut<'_, Result<(), TransportError>> {
        Box::pin(async move {
            if self.closed {
                return Ok(());
            }
            if !self.send_buf.is_empty() {
                let tail = std::mem::take(&mut self.send_buf);
                self.inner.send(Bytes::from(tail)).await?;
            }
            if !self.reorder_send.is_empty() {
                let flushed = self.flush(self.send_dir);
                self.ready_send.extend(flushed.frames);
            }
            self.pump_send().await?;
            self.inner.close().await?;
            self.closed = true;
            Ok(())
        })
    }
}

fn frame_meta(dir: Direction, frame: &[u8]) -> FrameMeta {
    let ty = frame.get(2).copied().unwrap_or(0);
    let seq = if frame.len() >= HEADER_LEN {
        u64::from_le_bytes([
            frame[13], frame[14], frame[15], frame[16], frame[17], frame[18], frame[19], frame[20],
        ])
    } else {
        0
    };
    FrameMeta::new(dir, ty, 0, seq)
}

/// Split complete frames out of a byte buffer.
///
/// A frame is `21-byte header + header.len` bytes. An incomplete tail stays in
/// `buffer` for the next call. A length above [`FRAME_MAX`] cannot be trusted,
/// so the whole buffer is emitted as one opaque chunk instead of waiting for
/// an impossible frame.
fn take_frames(buffer: &mut Vec<u8>) -> Vec<Bytes> {
    let mut frames = Vec::new();
    loop {
        if buffer.len() < HEADER_LEN {
            break;
        }
        let len = u32::from_le_bytes([buffer[9], buffer[10], buffer[11], buffer[12]]);
        if len > FRAME_MAX {
            frames.push(Bytes::from(std::mem::take(buffer)));
            break;
        }
        let total = HEADER_LEN + len as usize;
        if buffer.len() < total {
            break;
        }
        let rest = buffer.split_off(total);
        let frame = std::mem::replace(buffer, rest);
        frames.push(Bytes::from(frame));
    }
    frames
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn up(ty: u8, op_class: u8, seq: u64) -> FrameMeta {
        FrameMeta::new(Direction::Up, ty, op_class, seq)
    }

    /// W18: same seed and same frames produce the same decisions.
    #[test]
    fn u_testkit_faults_seed_reproducible() {
        let script = FaultScript::new(7).with_rule(
            FaultRule::new(Direction::Up, Selector::Any, Action::Drop).with_probability(0.5),
        );
        let mut first = FaultEngine::new(script.clone());
        let mut second = FaultEngine::new(script);

        let frames: Vec<FrameMeta> = (0..64).map(|seq| up(1, 0, seq)).collect();
        let first_run = first.decide_all(frames.iter().copied());
        let second_run = second.decide_all(frames.iter().copied());

        assert_eq!(first_run, second_run);
        assert_eq!(first.trace(), second.trace());
        assert!(first.trace().applied_count() > 0);
        assert!(first.trace().applied_count() < frames.len());
    }

    /// W18: different seeds produce a different random stream.
    #[test]
    fn u_testkit_faults_seed_changes_stream() {
        let mut first = FaultEngine::new(FaultScript::new(1).with_rule(
            FaultRule::new(Direction::Up, Selector::Any, Action::Drop).with_probability(1.0),
        ));
        let mut second = FaultEngine::new(FaultScript::new(2).with_rule(
            FaultRule::new(Direction::Up, Selector::Any, Action::Drop).with_probability(1.0),
        ));

        first.decide(up(1, 0, 0));
        second.decide(up(1, 0, 0));

        let first_roll = first.trace().entries()[0].decisions[0].roll;
        let second_roll = second.trace().entries()[0].decisions[0].roll;
        assert!(first_roll.is_some());
        assert!(second_roll.is_some());
        assert_ne!(first_roll, second_roll);
    }

    /// W18: drop, delay, duplicate and reorder are each selectable.
    #[test]
    fn u_testkit_faults_core_actions() {
        let script = FaultScript::new(11)
            .with_rule(FaultRule::new(
                Direction::Up,
                Selector::Type(1),
                Action::Drop,
            ))
            .with_rule(FaultRule::new(
                Direction::Up,
                Selector::Type(2),
                Action::Delay(Duration::from_millis(25)),
            ))
            .with_rule(FaultRule::new(
                Direction::Up,
                Selector::Type(3),
                Action::Duplicate(2),
            ))
            .with_rule(FaultRule::new(
                Direction::Up,
                Selector::Type(4),
                Action::Reorder(8),
            ));
        let mut engine = FaultEngine::new(script);

        assert_eq!(
            engine.decide(up(1, 0, 0)),
            Some(AppliedFault {
                rule_index: 0,
                action: Action::Drop,
            })
        );
        assert_eq!(
            engine.decide(up(2, 0, 1)),
            Some(AppliedFault {
                rule_index: 1,
                action: Action::Delay(Duration::from_millis(25)),
            })
        );
        assert_eq!(
            engine.decide(up(3, 0, 2)),
            Some(AppliedFault {
                rule_index: 2,
                action: Action::Duplicate(2),
            })
        );
        assert_eq!(
            engine.decide(up(4, 0, 3)),
            Some(AppliedFault {
                rule_index: 3,
                action: Action::Reorder(8),
            })
        );
        assert_eq!(engine.decide(up(5, 0, 4)), None);
    }

    /// W18: limit stops a rule after the configured number of applications.
    #[test]
    fn u_testkit_faults_limit() {
        let script = FaultScript::new(3)
            .with_rule(FaultRule::new(Direction::Up, Selector::Any, Action::Drop).with_limit(2));
        let mut engine = FaultEngine::new(script);
        let frames: Vec<FrameMeta> = (0..10).map(|seq| up(1, 0, seq)).collect();

        let outcomes = engine.decide_all(frames);
        let applied = outcomes.iter().filter(|outcome| outcome.is_some()).count();
        assert_eq!(applied, 2);
        assert_eq!(engine.trace().applied_count(), 2);

        let limited = engine
            .trace()
            .entries()
            .iter()
            .skip(2)
            .all(|entry| entry.decisions[0].limit_reached);
        assert!(limited);
    }

    /// W18: every selector kind filters as documented.
    #[test]
    fn u_testkit_faults_selectors() {
        let script = FaultScript::new(5)
            .with_rule(FaultRule::new(
                Direction::Up,
                Selector::Type(9),
                Action::Drop,
            ))
            .with_rule(FaultRule::new(
                Direction::Up,
                Selector::OpClass(3),
                Action::Close,
            ))
            .with_rule(FaultRule::new(
                Direction::Up,
                Selector::Seq(5),
                Action::TamperTag,
            ))
            .with_rule(FaultRule::new(
                Direction::Up,
                Selector::SeqRange(10, 12),
                Action::UnknownType(0x7F),
            ));
        let mut engine = FaultEngine::new(script);

        // 规则 0：type 9。
        assert_eq!(engine.decide(up(9, 0, 0)).map(|f| f.rule_index), Some(0));
        // 规则 1：op_class 3。
        assert_eq!(engine.decide(up(1, 3, 1)).map(|f| f.rule_index), Some(1));
        // 规则 2：seq 5。
        assert_eq!(engine.decide(up(1, 0, 5)).map(|f| f.rule_index), Some(2));
        // 规则 3：seq 区间 [10,12]。
        assert_eq!(engine.decide(up(1, 0, 11)).map(|f| f.rule_index), Some(3));
        assert_eq!(engine.decide(up(1, 0, 13)), None);
    }

    /// W18: Nth selects the n-th candidate frame (0-based).
    #[test]
    fn u_testkit_faults_nth() {
        let script = FaultScript::new(5).with_rule(FaultRule::new(
            Direction::Up,
            Selector::Nth(1),
            Action::Truncate { bytes: 4 },
        ));
        let mut engine = FaultEngine::new(script);

        assert_eq!(engine.decide(up(1, 0, 0)), None);
        assert_eq!(
            engine.decide(up(1, 0, 1)),
            Some(AppliedFault {
                rule_index: 0,
                action: Action::Truncate { bytes: 4 },
            })
        );
        assert_eq!(engine.decide(up(1, 0, 2)), None);
    }

    /// W18: probability 0.0 never applies, but rolls are recorded.
    #[test]
    fn u_testkit_faults_probability_zero() {
        let script = FaultScript::new(13).with_rule(
            FaultRule::new(Direction::Up, Selector::Any, Action::Drop).with_probability(0.0),
        );
        let mut engine = FaultEngine::new(script);
        for seq in 0..16 {
            assert_eq!(engine.decide(up(1, 0, seq)), None);
        }
        assert_eq!(engine.trace().applied_count(), 0);
        assert!(
            engine
                .trace()
                .entries()
                .iter()
                .all(|entry| entry.decisions[0].roll.is_some())
        );
    }

    /// W18: invalid probabilities are rejected before any frame is decided.
    #[test]
    fn u_testkit_faults_invalid_probability() {
        let too_large = FaultScript::new(1).with_rule(
            FaultRule::new(Direction::Up, Selector::Any, Action::Drop).with_probability(1.5),
        );
        assert_eq!(
            too_large.validate(),
            Err(FaultError::ProbabilityOutOfRange {
                rule_index: 0,
                probability: 1.5,
            })
        );
        assert!(FaultEngine::try_new(too_large).is_err());

        let not_finite = FaultScript::new(1).with_rule(
            FaultRule::new(Direction::Up, Selector::Any, Action::Drop).with_probability(f64::NAN),
        );
        assert_eq!(
            not_finite.validate(),
            Err(FaultError::NonFiniteProbability { rule_index: 0 })
        );
        assert!(FaultEngine::try_new(not_finite).is_err());
    }

    /// W18: trace records one entry per frame with per-rule decisions.
    #[test]
    fn u_testkit_faults_trace_records() {
        let script = FaultScript::new(17)
            .with_rule(FaultRule::new(Direction::Up, Selector::Any, Action::Drop))
            .with_rule(FaultRule::new(
                Direction::Down,
                Selector::Any,
                Action::Delay(Duration::from_millis(1)),
            ));
        let mut engine = FaultEngine::new(script);

        engine.decide(up(1, 0, 0));
        engine.decide(FrameMeta::new(Direction::Down, 1, 0, 1));

        let trace = engine.trace();
        assert_eq!(trace.len(), 2);
        assert_eq!(trace.entries()[0].frame_index, 0);
        assert_eq!(trace.entries()[1].frame_index, 1);
        // The first rule hits and breaks, so frame 0 records one decision.
        assert_eq!(trace.entries()[0].decisions.len(), 1);
        assert_eq!(trace.entries()[1].decisions.len(), 2);
        assert_eq!(trace.applied_count(), 2);
        assert!(!trace.is_empty());
    }

    #[derive(Default)]
    struct MockTransport {
        sent: std::sync::Arc<std::sync::Mutex<Vec<Bytes>>>,
        incoming: VecDeque<Bytes>,
    }

    impl Transport for MockTransport {
        fn send(&mut self, chunk: Bytes) -> BoxFut<'_, Result<(), TransportError>> {
            Box::pin(async move {
                self.sent.lock().unwrap().push(chunk);
                Ok(())
            })
        }

        fn recv(&mut self) -> BoxFut<'_, Result<Option<Bytes>, TransportError>> {
            Box::pin(async move { Ok(self.incoming.pop_front()) })
        }

        fn close(&mut self) -> BoxFut<'_, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn wire(ty: u8, seq: u64, body: &[u8]) -> Bytes {
        let mut out = vec![0u8; HEADER_LEN + body.len()];
        out[0] = crate::protocol::MAGIC;
        out[1] = 1;
        out[2] = ty;
        out[9..13].copy_from_slice(&(body.len() as u32).to_le_bytes());
        out[13..21].copy_from_slice(&seq.to_le_bytes());
        out[21..].copy_from_slice(body);
        Bytes::from(out)
    }

    fn mock() -> (MockTransport, std::sync::Arc<std::sync::Mutex<Vec<Bytes>>>) {
        let mock = MockTransport::default();
        let sent = std::sync::Arc::clone(&mock.sent);
        (mock, sent)
    }

    /// W18: the same seed and frame sequence produce the same bytes and trace.
    #[tokio::test]
    async fn u_testkit_faulty_drop_seeded_reproducible() {
        let script = FaultScript::new(0x51a7).with_rule(FaultRule::new(
            Direction::Up,
            Selector::Nth(1),
            Action::Drop,
        ));
        let (first_inner, first_sent) = mock();
        let (second_inner, second_sent) = mock();
        let mut first = FaultyTransport::wrap(Box::new(first_inner), script.clone());
        let mut second = FaultyTransport::wrap(Box::new(second_inner), script);

        for wrapper in [&mut first, &mut second] {
            for seq in 0..3 {
                wrapper
                    .send(wire(0x10, seq, &[seq as u8; 4]))
                    .await
                    .unwrap();
            }
        }

        let first_bytes = first_sent.lock().unwrap().clone();
        let second_bytes = second_sent.lock().unwrap().clone();
        assert_eq!(first_bytes, second_bytes);
        assert_eq!(first_bytes.len(), 2);
        assert_eq!(first.trace(), second.trace());
        assert_eq!(first.applied_count(), 1);
        assert_eq!(first.frames_sent(), 2);
    }

    /// W18: duplicate and reorder are applied to whole frames, deterministically.
    #[tokio::test]
    async fn u_testkit_faulty_duplicate_and_reorder() {
        let duplicate = FaultScript::new(0x51a8).with_rule(FaultRule::new(
            Direction::Up,
            Selector::Nth(0),
            Action::Duplicate(1),
        ));
        let (inner, sent) = mock();
        let mut wrapper = FaultyTransport::wrap(Box::new(inner), duplicate);
        wrapper.send(wire(0x10, 0, &[0xaa; 2])).await.unwrap();
        assert_eq!(sent.lock().unwrap().len(), 2);

        let reorder = FaultScript::new(0x51a9).with_rule(FaultRule::new(
            Direction::Up,
            Selector::Nth(0),
            Action::Reorder(3),
        ));
        let (inner, sent) = mock();
        let mut wrapper = FaultyTransport::wrap(Box::new(inner), reorder);
        for seq in 0..3 {
            wrapper
                .send(wire(0x10, seq, &[seq as u8; 2]))
                .await
                .unwrap();
        }
        let bytes = sent.lock().unwrap().clone();
        assert_eq!(bytes.len(), 3);
        let mut sequences: Vec<u64> = bytes
            .iter()
            .map(|frame| {
                u64::from_le_bytes([
                    frame[13], frame[14], frame[15], frame[16], frame[17], frame[18], frame[19],
                    frame[20],
                ])
            })
            .collect();
        sequences.sort_unstable();
        assert_eq!(sequences, vec![0, 1, 2]);
    }

    /// W18: a truncated frame models a half-written connection.
    #[tokio::test]
    async fn u_testkit_faulty_truncate_half_write() {
        let script = FaultScript::new(7).with_rule(FaultRule::new(
            Direction::Up,
            Selector::Nth(0),
            Action::Truncate { bytes: 10 },
        ));
        let (inner, sent) = mock();
        let mut wrapper = FaultyTransport::wrap(Box::new(inner), script);

        wrapper.send(wire(0x10, 0, &[0xaa; 32])).await.unwrap();
        let bytes = sent.lock().unwrap().clone();
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0].len(), 10);
    }

    /// W18: Close forwards the frame and then reports EOF / Disconnected.
    #[tokio::test]
    async fn u_testkit_faulty_close_eof() {
        let script = FaultScript::new(8).with_rule(FaultRule::new(
            Direction::Up,
            Selector::Nth(0),
            Action::Close,
        ));
        let (inner, sent) = mock();
        let mut wrapper = FaultyTransport::wrap(Box::new(inner), script);

        wrapper.send(wire(0x10, 0, &[1; 4])).await.unwrap();
        assert_eq!(sent.lock().unwrap().len(), 1);
        assert!(wrapper.is_closed());
        assert!(matches!(
            wrapper.send(wire(0x10, 1, &[2; 4])).await,
            Err(TransportError::Disconnected)
        ));
        assert!(wrapper.recv().await.unwrap().is_none());
    }

    /// W18: Delay consumes paused time instead of wall-clock sleep.
    #[tokio::test(start_paused = true)]
    async fn u_testkit_faulty_delay_paused_time() {
        let script = FaultScript::new(9).with_rule(FaultRule::new(
            Direction::Up,
            Selector::Nth(0),
            Action::Delay(Duration::from_millis(50)),
        ));
        let (inner, _sent) = mock();
        let mut wrapper = FaultyTransport::wrap(Box::new(inner), script);
        let started = tokio::time::Instant::now();
        wrapper.send(wire(0x10, 0, &[1; 4])).await.unwrap();
        assert!(started.elapsed() >= Duration::from_millis(50));
    }

    /// W18: corrupt, unknown-type and tag tamper rewrite the exact bytes.
    #[tokio::test]
    async fn u_testkit_faulty_corruptions() {
        let corrupt = FaultScript::new(10).with_rule(FaultRule::new(
            Direction::Up,
            Selector::Nth(0),
            Action::Corrupt {
                byte: 21,
                xor: 0xa5,
            },
        ));
        let (inner, sent) = mock();
        let mut wrapper = FaultyTransport::wrap(Box::new(inner), corrupt);
        wrapper.send(wire(0x10, 0, &[0; 4])).await.unwrap();
        assert_eq!(sent.lock().unwrap()[0][21], 0xa5);

        let unknown = FaultScript::new(11).with_rule(FaultRule::new(
            Direction::Up,
            Selector::Nth(0),
            Action::UnknownType(0x7f),
        ));
        let (inner, sent) = mock();
        let mut wrapper = FaultyTransport::wrap(Box::new(inner), unknown);
        wrapper.send(wire(0x10, 0, &[0; 4])).await.unwrap();
        assert_eq!(sent.lock().unwrap()[0][2], 0x7f);

        let tamper = FaultScript::new(12).with_rule(FaultRule::new(
            Direction::Up,
            Selector::Nth(0),
            Action::TamperTag,
        ));
        let (inner, sent) = mock();
        let mut wrapper = FaultyTransport::wrap(Box::new(inner), tamper);
        wrapper.send(wire(0x10, 0, &[0; 4])).await.unwrap();
        assert_eq!(sent.lock().unwrap()[0].last(), Some(&0xff));
    }

    /// W18: downlink faults select by direction and drop only the chosen frame.
    #[tokio::test]
    async fn u_testkit_faulty_downlink_drop() {
        let script = FaultScript::new(13).with_rule(FaultRule::new(
            Direction::Down,
            Selector::Nth(0),
            Action::Drop,
        ));
        let mut inner = MockTransport::default();
        inner.incoming.push_back(wire(0x10, 1, &[1; 4]));
        inner.incoming.push_back(wire(0x10, 2, &[2; 4]));
        let mut wrapper = FaultyTransport::wrap(Box::new(inner), script);

        let received = wrapper.recv().await.unwrap().unwrap();
        assert_eq!(received[13..21], 2u64.to_le_bytes());
        assert!(wrapper.recv().await.unwrap().is_none());
        assert_eq!(wrapper.frames_recv(), 1);
    }

    /// W18: Blackhole swallows bytes without an EOF, then recovers.
    #[tokio::test(start_paused = true)]
    async fn u_testkit_faulty_blackhole_no_eof() {
        let script = FaultScript::new(14).with_rule(FaultRule::new(
            Direction::Down,
            Selector::Nth(0),
            Action::Blackhole(Duration::from_millis(20)),
        ));
        let mut inner = MockTransport::default();
        inner.incoming.push_back(wire(0x10, 1, &[1; 4]));
        inner.incoming.push_back(wire(0x10, 2, &[2; 4]));
        let mut wrapper = FaultyTransport::wrap(Box::new(inner), script);

        assert!(
            tokio::time::timeout(Duration::from_millis(1), wrapper.recv())
                .await
                .is_err()
        );
        let received = wrapper.recv().await.unwrap().unwrap();
        assert_eq!(received[13..21], 2u64.to_le_bytes());
    }
}
