# 故障注入手册

本文件定义 W19 混沌配方的注入接缝。目标是**可复现**：同一 seed、同一帧序列、同一脚本，必须得到同一决策序列和同一证据行。

## 1. 设计原则

1. **最低可观察层**：协议语义用帧级代理；连接语义用字节级代理；时间用 `TestClock`；本地写用 store 装饰器；进程崩溃用 failpoint/kill。不要为了“更真实”把每个用例搬到 FUSE。
2. **确定性**：故障决策只用 seed 驱动的自包含 RNG；禁止无 seed 随机、禁止 `sleep` 等待收敛。
3. **fail-closed**：损坏、伪造、未知类型、错误 PSK 的默认期望是拒绝/卸载，不是“跳过继续”。
4. **显式失败**：失败写必须返回 errno，队列满必须 KICK，缺口必须 resync；不允许静默丢帧/丢 op。
5. **现实性标注**：每个故障标注 realistic 或 adversarial；标注不改变安全门槛，只用于解释覆盖范围。
6. **测试替身不污染产品**：所有注入只在 `testkit`/测试进程内；release 不含相关符号。

## 2. 注入层总表

| 层 | 接缝 | 覆盖 | 特权 |
|---|---|---|---|
| L0 决策引擎 | `FaultEngine::decide(FrameMeta)` | F1–F5、F9、F15、F22 的帧级决策；F17/F23 用夹具或直接构造 | 无 |
| L1 帧级代理 | `FrameProxy`，整帧转发 | F1–F5、F9、F15、F22、F23 的帧级动作；签名伪造用夹具 | 无 |
| L2 字节级代理 | `TcpProxy`，TCP 连接 | FIN/RST、半开/黑洞 | 无 |
| L3 时钟 | `TestClock`，显式 `Instant` | F10–F12 | 无 |
| L4 本地写路径 | outbox 容量、只读 backing；`FaultyStore` 为配方要求 | F13、F14 | 无 |
| L5 staging/进程 | failpoint、`kill -9`、`cleanup_stale` | F18、F19 | 无 |
| L6 身份/密钥 | 错误 PSK、签名/AEAD 篡改、KeyAnnounce 重放 | F16、F23 | 无 |
| L7 水位线控制面 | 伪造 HELLO/PING 报告、显式 `tick` | F20、W1–W7 | 无 |

当前仓库没有独立 `fault-proxy` 二进制；L1/L2 都在测试进程内。若后续拆出独立代理，控制面契约见 §5.3。

## 3. FaultScript 契约

### 3.1 数据结构

| 字段 | 类型 | 语义 |
|---|---|---|
| `seed` | `u64` | 决策 RNG 种子；同一 seed + 同一帧序列 ⇒ 同一决策 |
| `rules` | `Vec<FaultRule>` | 按顺序判定，第一条命中即生效 |
| `dir` | `Up` / `Down` / `Both` | 只匹配该方向；`FrameMeta` 实际方向只能是 `Up`/`Down` |
| `selector` | `Any` / `Type(u8)` / `OpClass(u8)` / `Seq(u64)` / `SeqRange(u64,u64)` / `Nth(usize)` | 选择命中的帧；`Nth` 从 0 开始，按该规则方向匹配计数 |
| `action` | `Drop` / `Duplicate(u8)` / `Delay(Duration)` / `Reorder(u16)` / `Corrupt{byte,xor}` / `Truncate{bytes}` / `Close` / `Blackhole(Duration)` / `UnknownType(u8)` / `TamperTag` | 对命中帧执行的动作 |
| `probability` | `f64` | `[0.0, 1.0]`；非有限或越界在构造时拒绝 |
| `limit` | `Option<usize>` | 最多应用次数；`None` 不限 |

示例（当前 testkit API）：

```rust
use syncmount::testkit::{
    Direction, FaultAction, FaultRule, FaultScript, Selector,
};

let script = FaultScript::new(0x4d02).with_rule(
    FaultRule::new(Direction::Down, Selector::Any, FaultAction::Drop)
        .with_probability(0.05),
);
```

规则顺序很重要：先写“只丢第 0 帧”的 `Nth(0)`，再写“5% 丢任意帧”的 `Any`，否则前者可能被后者先命中。

### 3.2 决策与轨迹

```text
FrameMeta { dir, ty, op_class, seq }
    -> FaultEngine::decide
    -> Option<AppliedFault { rule_index, action }>
```

- 每帧记录一条 `TraceEntry`：`frame_index`、`meta`、每条规则的 `matched_direction`/`matched_selector`/`limit_reached`/`roll`/`applied`、最终 `applied`。
- 失败时用同一 seed 重放；`FaultTrace` 是证据的一部分，写入 `faults.jsonl`。
- 概率掷骰值只在方向与选择器都命中且未超限时记录；这样能区分“没命中”与“掷骰未中”。
- 随机源是自包含 SplitMix64；不依赖 `rand`/`rand_chacha` 版本行为。

### 3.3 常用 seed

| 用途 | seed |
|---|---|
| drop nth | `0x51a7` |
| duplicate nth | `0x51a8` |
| reorder first | `0x51a9` |
| delay nth | `0x51aa` |
| corrupt nth | `0x51ab` |
| tamper tag nth | `0x51ac` |
| unknown type nth | `0x51ad` |
| M4-2 5% loss soak | `0x4d02` |

新增随机场景必须支持 `SM_CHAOS_SEED` 覆盖；证据行打印实际 seed。

## 4. 帧级代理 FrameProxy

### 4.1 契约

- 输入完整帧（含 21B 帧头）；只解码帧头做选择器匹配，不解析 HTTP、不解析业务体。
- 每个方向一个实例；`pass` 输出零个或多个帧（`Drop` 输出零个，`Duplicate(n)` 输出 n+1 个）。
- `Delay` 阻塞该方向的转发循环，形成真实代理的 head-of-line 行为。
- `Reorder(window)`：第一个命中帧打开窗口；后续帧进入缓冲，窗口满后按确定性顺序释放。当前实现为窗口内逆序释放，所以 `window=2` 对 `[1,2,3]` 产生 `[2,1,3]`。需要随机洗牌时用多个 seed 或扩展实现。
- `Close` 返回 `ProxyStop::Close`，调用方关闭逻辑连接；`Blackhole` 返回 `ProxyStop::Blackhole`，调用方停止转发但不发 FIN。
- 流结束时 `flush()` 按序释放残余重排缓冲，避免测试悬挂。
- `applied()` 返回实际注入的帧数；必须断言 `>0`，防止“故障规则从未命中”的假通过。

### 4.2 动作语义

| 动作 | 语义 | 预期结果 |
|---|---|---|
| `Drop` | 丢弃该帧 | 缺口/丢 op；由上层检测 |
| `Duplicate(n)` | 额外复制 n 份 | 幂等丢弃；不重复应用 |
| `Delay(d)` | 延迟 d 后转发 | 收敛变慢；不改变终态 |
| `Reorder(w)` | 缓冲 w 帧后释放 | 乱序缓冲；不触发 resync |
| `Corrupt{byte,xor}` | 翻转指定字节 | AEAD/签名拒绝；不 apply |
| `Truncate{bytes}` | 截断到指定长度 | 解码错误/连接错误；不 apply |
| `Close` | 该帧后关闭 | 立即卸载/EOF |
| `Blackhole(d)` | 静默 d，不发 FIN | 心跳超时；不依赖 TCP 信号 |
| `UnknownType(t)` | 改写帧头 type | fail-closed；不推进 seq |
| `TamperTag` | 翻转最后一个字节（tag） | AEAD 拒绝；不 apply |

### 4.3 辅助脚本

当前测试提供以下工厂，均返回独立 `FaultScript`，测试持有 trace：

```text
drop_nth(dir, n)
duplicate_nth(dir, n, copies)
reorder_first(dir, window)
delay_nth(dir, n, delay)
corrupt_nth(dir, n, byte)
tamper_tag_nth(dir, n)
unknown_type_nth(dir, n, raw)
```

## 5. 字节级代理 TcpProxy

### 5.1 模式

| 模式 | 行为 | 覆盖 |
|---|---|---|
| `Pass` | 双向原样转发 | 基线 |
| `Blackhole` | 停止读/写，保持 socket 打开，不发 FIN/RST；切回 `Pass` 后恢复 | F7 半开 |
| `Close` | 关闭写半端，连接结束 | F6/F18 断连 |

- 当前 `TcpProxy` 只有一个共享模式开关，适合“单客户端整条连接”故障；R2/R7 的 per-connection profile 需要扩展为每连接独立开关。
- 不解析 HTTP；不模拟丢包/延迟/重复。这些用帧级代理或 netem。
- `Drop` 当前没有单独实现；需要字节丢包时用 `FrameProxy`（帧级）或扩展 `TcpProxy`。

### 5.2 半开语义

`Blackhole` 的关键不是“断”，而是“没有断的信号”：客户端 read 不返回 EOF，write 可能成功但永远不到对端。服务端不再有应用层存活计时器：F7 连续 `tick(+16s/+60s/+120s/+600s)` 后会话仍在线且不产生 KICK。真实断网由内核 keepalive（60s 空闲、10s 间隔、3 次探测）报告 transport 错误，随后移除会话；应用层代理仍由自己的内核回应 keepalive 探测，因此无法在本测试中制造该错误，sockopt 由 `u_http_keepalive_options_on_both_ends` 覆盖。

### 5.3 独立 fault-proxy 控制面（可选扩展）

若把代理拆成独立进程，控制面按 45 §3.8：

```text
Unix socket + JSON lines
命令: profile / partition / heal / stats / reset
Profile: delay_ms, jitter_ms, loss_pct, dup_pct, bw_limit_bps, silent_ms
```

- 所有命令幂等；每连接独立 profile；支持“只慢一个客户端”。
- `silent_ms` 模拟半开：不读不写，不发 FIN。
- `loss_pct` 是字节级丢弃/损坏，会破坏 HTTP chunked 流，等价于连接错误；不是 IP 丢包。真实 IP 丢包用 `tc netem`，需 CAP_NET_ADMIN，默认不进 CI。

## 6. 时钟注入

- `TestClock::new(start_us)`、`set`、`advance`、`rollback`；所有方法 `&self`，可 `Arc` 共享。
- 排序只用 `seq`；`WallClock` 只服务超时、mtime、审计时间，不参与排序。
- 服务器 health 判定用显式 `Instant`（`tick(base + d)`），不 sleep；这样“空闲 10min”不花 10min。
- `Timeouts::production()` 是冻结常数：unmount_flush 2s、join 5s、rtt_window 60、rtt_default 300ms、stall_cap 24h、min_throughput 1MiB/s、op_apply 100ms。心跳窗口已删除：存活由 TCP 连接与内核 keepalive（60s/10s/3）判断。`Timeouts::for_tests()` 只缩小时间，不改变语义比例。
- 进程级时钟可用 `libfaketime`，缺失时 skip 并记录；主逻辑用进程内 `TestClock`。

## 7. 本地写路径故障

### 7.1 配方要求

| 故障 | 注入 | 预期 |
|---|---|---|
| ENOSPC | `FaultyStore` 返回 `Enospc`；或 backing 占满 | FUSE ENOSPC；失败写不产生 op；无半写 |
| EIO | `FaultyStore` 返回 `Eio` | FUSE EIO；无 op |
| 短写 | `FaultyStore` 返回部分计数 | 按 POSIX 返回部分写；不静默补全 |
| 延迟 | `FaultyStore::Delay` | 触发 coalescer/背压；不改变正确性 |

`FaultyStore` 是装饰器：生产用真实 `LocalStore`，测试包一层；不污染产品路径。

### 7.2 当前近似

- F13 用客户端 outbox 容量耗尽（`cap_bytes=8`、`cap_ops=1`）得到 ENOSPC；断言失败 admission 不增加 op。服务器是纯定序器，没有可满的磁盘。
- F14 用只读 backing（mode 0444）得到 EACCES/EROFS；断言失败写零 op、本地文件不变。
- 这两条覆盖“失败写不产生 op”的语义，但不覆盖真实 `pwrite64/fsync` 错误与短写。补齐方式见 `scenarios.md` G4。

### 7.3 进程级

`LD_PRELOAD` 拦截 `pwrite64/fsync` 可精确命中 syncmount 对 backing 的写；`dm-flakey`/`dm-delay` 需要 root，只作夜间增强。默认不用特权路径。

## 8. staging、failpoint 与进程崩溃

### 8.1 failpoint 名称

| 名称 | 位置 | 用途 |
|---|---|---|
| `after_local_write_before_enqueue` | 客户端写路径 | 写成功但未入队时崩溃 → 无 op、本地有数据 |
| `after_enqueue_before_send` | outbox 发送前 | 未发出 op 随进程退出丢弃 |
| `after_send_before_ack` | 发送后 | 服务器已收/未收边界 |
| `join_after_manifest` | 加入同步 | 崩溃后 staging 清理 |
| `join_after_stage_fsync` | staging fsync 后 | 旧树仍完整 |
| `join_before_rename1/2/3` | rename×2 交换 | 任一时刻旧树或新树完整 |
| `unmount_after_quiesce` | 卸载 | flush 前崩溃 |
| `unmount_after_flush` | 卸载 | flush 后崩溃，本地数据在 |
| `snapshot_before_finalize` | 快照 | 半成品快照不可用 |
| `server_before_broadcast` | 广播前 | seq 已分配但未广播；epoch 变化兜底 |

触发方式：进程内 `FailPoint::set(name, Action)`/`FailPointGuard`；进程级 `SYNCMOUNT_FAILPOINT=name[,name...]`（命中即 panic）。名称集中在 `testkit::failpoints::names`，禁止散落字符串。

### 8.2 staging 崩溃

- staging 布局：`.syncmount-staging/{tree,chunks,trash,tmp,join.journal}`；用户树永远没有 `*.sm-tmp`。
- 崩溃后重挂载：`cleanup_stale` 清空 `tree/trash/tmp`，保留 chunk 缓存；用户树是“部分新 + 部分旧”，但没有半写文件。
- F19 当前只验证残留清理；完整配方要求 5 个 JOIN failpoint 各杀一次，断言旧树或新树完整。

### 8.3 进程崩溃

- 客户端 `kill -9`：auto_unmount 生效；重挂载 cluster-wins；不重放 journal；审计计数与实际删除一致。
- 服务器 `kill -9`：新 epoch、seq=0；所有在线客户端 Full resync；不承诺 acked 写持久。
- 崩溃残留只在隐藏区；`/proc/mounts` 必须无残留。

## 9. 身份与密钥故障

| 故障 | 注入 | 预期 |
|---|---|---|
| 错误 PSK | 客户端用翻转字节的 master password 派生 | JOIN_PROOF/AUTH 失败；不 STEADY；零 op；exit 2 或 KICK |
| 伪造签名 | 用 B 的私钥签 A 的 client_id | 验签失败；不 apply |
| 篡改 payload hash | 改 `SignedOp.payload_hash` | 验签失败；不 apply |
| 重放 KeyAnnounce | 同 seq 再 apply | 幂等；不重复加 key |
| 改帧头/AAD | 改 flags/seq/route 但不重算 AAD | AEAD 失败；不 apply |
| 篡改 tag | 翻转密文最后字节 | AEAD 失败；不 apply |

注意：**空集群首客户端**当前被信任（`TRN_NO_PEER`），没有验证者可拒绝错误 PSK。这是 SAFE-4 的已知边界，见 `scenarios.md` G5。

## 10. 水位线控制面

### 10.1 上报

- `CtrlPrefix` 18B：`applied_seq` + `reserved`；HELLO/PING 每次上报。
- 服务器每次上报都校验：`applied_seq` 单调、不超 `current_seq`、epoch 匹配；非法立即 KICK。
- 当前 `reserved` 固定 0，RTT 不上报；T1 网络项固定 300ms fallback（known_gap）。

### 10.2 判定

| 判定 | 触发 | 结果 |
|---|---|---|
| T1 Stalled | busy 且超过 `3×RTT_p99 + backlog/1MiBps + pending_ops×100ms`（上限 24h） | KICK `Stalled`；客户端 exit 10 |
| T2 Regression | `applied_seq` 回退 | 立即 KICK `Regression` |
| T3 Overclaim | `applied_seq > current_seq` | 立即 KICK `Overclaim` |
| T4 DuplicateClient | 同 client_id 新 HELLO | 踢旧留新；旧收 `DuplicateClient` reason=3；新进 Online；旧不再收 ORDERED；relay 槽释放 |
| T5 HeartbeatTimeout | >15s 无 PING/HELLO | 踢出；客户端卸载 |

busy = `current_seq > applied_seq || backlog_bytes > 0`；空闲不踢。1s tick；不得出现 60s floor 或 5×gap_p99。

## 11. seed、trace 与证据

```text
seed=<u64>
test=<full::test::path>
acceptance=<F/D/W/M4>
fault_trace=<faults.jsonl>
oplog=<oplog.jsonl>
manifests=<dir>
logs=<dir>
```

- 失败时保留 `FaultTrace.entries`：每帧的 `meta`、规则判定、最终动作。
- 证据行必须包含实际 seed 与 `applied_count`；`applied_count=0` 视为测试无效，不是通过。
- 对照跑（无故障）与故障跑的 manifest root 必须逐字节相同；不同则输出 `ManifestDiff` 与首个差异路径。
- 保留 14 天；失败 artifact 永久链接进 issue。

## 12. 新增故障的步骤

1. 在 `scenarios.md` 选 F/D/W 编号，写清注入点、预期、SAFE/LIVE 断言。
2. 选最低层接缝；优先 `FaultEngine` 的 selector/action，其次帧代理，最后字节代理。
3. 定义 seed、概率、limit；保证 `applied_count>0`。
4. 先写安全断言，再写活性断言；安全断言失败不重试。
5. 加无故障对照，比较 manifest root。
6. 更新 `scenarios.md` 的 F 表、F×S 矩阵、D/W 映射。
7. 若进 M4 runner，更新内部 M4 runner 的 `ITEMS` 与 `summarize.py`（未随仓库发布）。
8. 跑单项、跑全量、检查无静默 skip；记录证据行。
9. 失败最小化：同 seed 重放 → 缩短 recipe → 二分规则 → 最小脚本。

## 13. 现实性与盲区

| 故障 | 现实性 | 说明 |
|---|---|---|
| F1–F4 帧级丢/重/乱序 | adversarial | 真实 TCP 不这样；这是协议防御/中继 bug 测试，仍必须过 |
| F5 延迟 | realistic | 真实网络常见 |
| F6 FIN/RST | realistic | 真实断连 |
| F7 半开 | realistic | NAT/防火墙常见；proxy 近似 |
| F8/F12 重启 | realistic | 进程/主机重启 |
| F10–F12 时钟 | realistic | NTP 回拨/前跳 |
| F13/F14 磁盘 | realistic | 磁盘满/EIO |
| F15 位翻转 | realistic | 存储/网络位翻转 |
| F16/F17 密钥/重放 | realistic | 错误配置/攻击 |
| F18/F19 崩溃 | realistic | kill -9/断电 |
| F20 水位线违例 | adversarial | 伪造客户端 |
| F21/F22 版本偏斜 | realistic | 混合版本 |
| F23 签名伪造/篡改 | adversarial | 恶意服务器/成员 |
| F24 锁竞争 | realistic | 多客户端 |

**不覆盖**：

- 产品逻辑 bug 产生“格式正确的错误 op”——那是协议 fuzzing。
- 内容级 fsck：混沌只断言 manifest root 相同，不证明内容级正确。
- 真实多机/NAT/Wi-Fi 漫游：单机 proxy 近似。
- 内核 OOM、磁盘固件错误、文件系统损坏。
- `tc netem` 的真实 TCP 重传/窗口行为：需 CAP_NET_ADMIN，夜间增强。

## 14. 注入保真度缺口

| # | 缺口 | 影响 |
|---|---|---|
| I1 | 无独立 fault-proxy 二进制；无 per-connection profile | R2/R7 的“只慢一个客户端”需扩展 |
| I2 | `TcpProxy` 只有 Pass/Blackhole/Close；无字节级 loss/dup/delay | 真实网络抖动靠帧代理或 netem |
| I3 | `FrameProxy` reorder 是窗口内逆序，不是随机洗牌 | 乱序覆盖有限；需多 seed/扩展 |
| I4 | 无 `FaultyStore` 实现；F13/F14 用 outbox/只读 backing 近似 | 真实 ENOSPC/EIO/短写未覆盖 |
| I5 | 无 `libfaketime` 进程级注入；只用 `TestClock` | 真实系统调用时钟未覆盖 |
| I6 | 无 netem/iptables 路径 | 真实 TCP 栈行为未覆盖 |
| I7 | 无 1s/1024 帧 reorder buffer 上限注入 | F2 的预算断言未覆盖 |
| I8 | 无 30min soak 默认门禁 | M4-2 记录运行 180s |

这些缺口不改变安全断言的判定，但必须在覆盖报告中显式列出，不能当成“已覆盖”。
