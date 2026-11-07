# W19 混沌测试配方（F1–F24 / D1–D16 / W1–W7）

状态：配方与当前落地映射。只描述测试，不含产品代码。
权威顺序：`39-s1-spec.md` > `31-acceptance.md` > `45-test-skeleton.md` > `34-chaos-test.md` > 本目录。
实现归属：`tests/chaos/*.rs` 与 `tests/chaos_matrix.rs` 由 W19 owner 维护；M4 验收 runner 属内部验收记录，未随仓库发布。本目录三个 Markdown 文件是配方契约。
配方以可观察行为与注入接缝为准；文中的测试名/类型名只用于定位当前落地，替换实现不必保留命名。

## 1. 范围

| 层 | 内容 | 本文档 |
|---|---|---|
| F | F1–F24 单故障注入：丢包、乱序、重复、延迟、断连、半开、服务器重启、时钟回拨、磁盘满、写盘失败、解密失败、PSK 错误、重放、进程崩溃、版本偏斜、签名篡改、锁语义 | `scenarios.md` §3 |
| R | R1–R13 组合配方：烂网络、半开地狱、重启风暴、磁盘满、时钟错乱、密钥混乱、慢消费者、崩溃循环、staging 崩溃、水位线违例、上行吞帧、下行分类、签名/锁/seq 组合 | `scenarios.md` §4 |
| D | D1–D16 分布式场景到故障注入与现有测试的映射 | `scenarios.md` §5 |
| W | W1–W7 水位线场景到 M4-10..16 的映射 | `scenarios.md` §6 |
| 注入 | 帧级/字节级代理、确定性故障脚本、TestClock、failpoint、本地写故障、身份故障 | `faults.md` |

主场景计数：F1–F24（24）+ D1–D16（16）+ W1–W7（7）= 47；另有 F5b、W1b 两个子项与 R1–R13 组合配方。

配方不绑定实现：只要求等价的注入能力（帧级选择器、连接级模式、时钟/存储/身份接缝）；当前 `FrameProxy`/`TcpProxy`/`FaultEngine` 是参考实现。

**非目标**：不在混沌层建立正确性基线；不替代 I/F 层的 POSIX 与协议测试；不做内容级 fsck；不模拟真实多机、NAT、Wi-Fi 漫游；不覆盖“产品逻辑 bug 产生格式正确的错误 op”（那是协议 fuzzing）。

## 2. 文件

```text
tests/chaos/
├── README.md        # 本文件：入口、运行、判定、证据
├── scenarios.md     # F1–F24、R1–R13、D1–D16、W1–W7 的行为与断言
├── faults.md        # 注入接缝、FaultScript、代理、时钟、存储、身份、seed
├── faults.rs        # F1–F24 测试（W19 owner）
├── watermark.rs     # W1–W7 测试（W19 owner）
├── m4.rs            # M4-1..9 验收测试（W19 owner）
├── harness.rs       # 进程内 sequencer/HTTP/FUSE harness（W19 owner）
├── proxy.rs         # FrameProxy/TcpProxy（W19 owner）
└── mod.rs           # 模块声明（W19 owner）
```

本目录的 `.md` 不编译、不进发布物。任何产品代码、`Cargo.toml`、`src/lib.rs`、CI 的修改都不属于本配方。

## 3. 运行

### 3.1 前置

| 项 | 要求 | 影响 |
|---|---|---|
| OS | Linux x86_64 | 全部 |
| 工具链 | `rustc 1.85.0`（`rust-toolchain.toml`） | 全部 |
| `/dev/fuse` | 可打开 | F16、W6、W7、M4-1；缺失时这些用例 panic，不静默 skip |
| `fusermount3` | 可用，setuid | 同上 |
| 磁盘 | `/tmp` 至少 2 GiB 可用 | 100 MiB 大文件、日志、临时 backing |
| 权限 | 普通用户 | 不需要 root、`tc`、`iptables`、`CAP_NET_ADMIN` |
| feature | 保持默认 `fuse`；显式加 `testkit,chaos-tests` | F13/F14/F24 是 `#[cfg(feature = "fuse")]`；F16/W6/W7/M4-1 需要 `fuse` 才能挂载；F13/F14/F24/M4-6 只需 feature，不挂载 |

### 3.2 全量

```bash
cd ~/syncmount
cargo +1.85.0 test --test chaos_matrix \
  --features testkit,chaos-tests \
  -- --test-threads=1 --nocapture
```

`--test-threads=1` 是硬要求：FUSE 挂载、临时目录、端口、全局 failpoint 都按串行设计。

### 3.3 单项

```bash
cargo +1.85.0 test --test chaos_matrix \
  --features testkit,chaos-tests \
  -- --exact --nocapture --test-threads=1 \
  chaos::faults::f2_downlink_loss_is_detected_as_a_seq_gap
```

`--exact` 后跟完整测试路径。F1–F24 在 `chaos::faults`，W1–W7 在 `chaos::watermark`，M4-1..9 在 `chaos::m4`。

### 3.4 证据 runner

M4 验收 runner 是内部工具，未随仓库发布。它逐项执行 F1–F24（含 F5b）、
W1–W7（含 W1b）、M4-1..9，默认把 M4-2 soak 缩短为 180s，验收档使用
30min soak。输出布局：

| 产物 | 内容 |
|---|---|
| `logs/<item>.log` | 单项完整输出，含 `chaos evidence:` 行 |
| `results.tsv` | `item / pass/fail / duration / log` |
| `summary.json` | 逐项 verdict、证据行、known gap、验收映射 |
| `environment.txt` | 日期、host、commit、worktree、工具链、资源 |

runner 的退出码只表示脚本自身；判定看 `summary.json`。单项失败不会被隐藏。

### 3.5 时长档

| 档 | 范围 | 目标墙钟 | 触发 |
|---|---|---|---|
| smoke | F1–F5、F10、F15、F21–F23；W1–W5（进程内） | < 10s | 本地提交前 |
| default | F1–F24、W1–W7、M4-1..9；M4-2 180s | ≈ 200s | 每次改动 / 夜间 |
| acceptance | default + `SM_M4_SOAK_SECS=1800` | ≈ 35min | M4 门禁 |
| nightly | R1–R13 全矩阵，N=30/50，含对照 | 90–180min | 发布前 / 夜间 |

当前 runner 只覆盖 default/acceptance；nightly 的 R1–R13 是配方目标，需 W19 owner 按 `scenarios.md` §4 扩展。

### 3.6 fault proxy 的形态

当前没有独立 `fault-proxy` 进程：帧级 `FrameProxy` 与字节级 `TcpProxy` 都在测试进程内，随 `cargo test` 启动，不需要端口、控制 socket 或 root。每个用例自己构造 `FaultScript` 和代理模式。

若后续拆出独立代理，按 `faults.md` §5.3 的 Unix socket + JSON lines 控制面运行；client/server 只改 endpoint，测试通过 `profile/partition/heal/stats/reset` 控制。两种形态的注入语义必须一致。

## 4. seed 与确定性

- 每个注入用例有显式 seed；非注入用例用固定夹具。失败输出必须带 seed。
- 故障引擎使用自包含 SplitMix64：同一 seed + 同一帧序列 ⇒ 同一决策序列，不依赖 `rand` 版本。
- 常用 seed：`drop=0x51a7`、`duplicate=0x51a8`、`reorder=0x51a9`、`delay=0x51aa`、`corrupt=0x51ab`、`tamper_tag=0x51ac`、`unknown_type=0x51ad`；M4-2 soak 用 `0x4d02`。
- 规则按顺序判定，第一条命中即生效；`probability` 与 `limit` 必须显式。
- 新增随机场景必须支持 `SM_CHAOS_SEED` 覆盖，并在证据行打印实际 seed；当前固定常量是基线。
- 禁止无 seed 的随机、禁止 `sleep` 等待收敛、禁止测试间共享挂载点/端口/临时目录。

## 5. 证据

配方要求每个用例至少留下（当前 M4 runner 只保证 `chaos evidence:` 行与日志；新增用例必须补齐 seed/artifacts）：

```text
chaos evidence: <ID> <pass|fail> key=value ...
seed=<seed> test=<name> acceptance=<D/W/M4/F> artifacts=<dir>
```

失败时必须额外落盘：

- `manifests/`：各端 manifest 与 root；
- `oplog.jsonl`：服务器 ORDERED 记录；
- `trace.jsonl`：状态迁移与故障决策；
- `faults.jsonl`：FaultTrace；
- `logs/`：客户端/服务器 JSON 日志；
- `mounts.txt`：`/proc/mounts` 快照。

长期目标路径是 `target/test-artifacts/<test>/<seed>/result.json`（45 §7.4）；当前 M4 runner 汇总到内部 `summary.json`（未随仓库发布）。两者都必须保留 14 天，失败 artifact 永久链接进 issue。

## 6. 判定

### 6.1 安全断言（零容忍）

任一次违反即阻塞发版；安全测试不重试。

| ID | 断言 | 定义 |
|---|---|---|
| SAFE-1 | 无静默分叉 | quiescence 时所有 STEADY 客户端 `manifest_root` 相同；不同必须有 resync/unmount/删除事件解释 |
| SAFE-2 | 无撕裂 | op 粒度原子；同偏移终态字节来自单一 op，或可由 seq 全序解释；`applied_seq >= op.seq` 后不得只见部分 op |
| SAFE-3 | 无幽灵 | 路径存在性/内容可由 op log/snapshot 推导；无幽灵会话；用户树无临时文件；内部项不可见 |
| SAFE-4 | 错误 PSK 不进 STEADY | 错误密钥零 op 上行、不挂载、不进入 STEADY；验签失败 fail-closed |
| SAFE-5 | 无静默 seq 空洞 | 缺口必须显式 `SeqGap`/`Rollback`/KICK；重复丢弃；不重发、不静默跳过 |
| SAFE-6 | 无部分应用/无回滚 | AEAD/签名失败零 apply；重放不重复应用；跨 epoch 不比较 applied_seq |
| SAFE-7 | 交换原子 | JOIN staging 交换任一时刻旧树或新树完整；崩溃残留只在 `.syncmount-staging` |
| SAFE-8 | 锁语义正确 | flock 仅本机且不阻塞其他端；fcntl 跨端互斥；F_GETLK 跨端；LEAVE 释放 fcntl；死锁牺牲者确定 |

### 6.2 活性断言（故障消除后）

| ID | 断言 |
|---|---|
| LIVE-1 | 收敛 p99 < 120s；故障消除后所有在线客户端达到 quiescence |
| LIVE-2 | 断线检测 ≤ 15s 心跳超时 + 抖动；卸载 < 1s；无 OFFLINE 宽限 |
| LIVE-3 | 无故障对照跑同一操作序列，终态 manifest root 逐字节相同 |
| LIVE-4 | 失败必须显式：ENOSPC/EIO/EACCES/EEXIST/ENOTEMPTY 等 errno 或 KICK，不静默成功 |

### 6.3 禁止的观测

- 两端 STEADY 但 manifest root 不同，且无解释事件；
- 同偏移字节混合来自两个 op；
- 路径在一端存在、另一端不存在，且 op log 无法推导；
- 错误 PSK 客户端进入 STEADY 或产生任何 op；
- 广播队列满却无 KICK，后续 seq 直接跳过；
- 损坏帧被部分应用；
- 用户树出现 `*.sm-tmp` / `.syncmount-tmp.*`；
- 故障规则从未命中（`applied_count=0`）却判通过；
- 测试静默 skip（FUSE 缺失时 F16/W6/W7/M4-1 必须失败）。

## 7. 当前状态

2026-11-07 记录（commit `c6d601e`，worktree dirty）：

| 项 | 结果 |
|---|---|
| F1–F24 + F5b | 25/25 pass |
| W1–W7 + W1b | 8/8 执行；W1/W1b 为 known_gap（RTT 未上报） |
| M4-1..9 | 9/9 pass |
| 汇总 | 40 pass、0 fail、2 known_gap；`overall=pass_with_known_gaps` |

已知产品/配方缺口（详见 `scenarios.md` §7）：

1. **F16 空集群首客户端**：没有验证者时首个客户端被信任，错误 PSK 可加入空集群。这是 SAFE-4 的边界缺口，需产品裁决。
2. **W1/W1b RTT**：`ctrl_prefix.reserved` 固定 0，RTT 永不上报；T1 阈值固定 300ms fallback，与 45 的 `reserved=rtt_ms` 冲突。
3. **F1 客户端侧检测**：当前只证明服务端不静默定序 + 水位线 Stalled；未覆盖 `UplinkLost`/`UplinkStall`。
4. **F2 分类**：当前只覆盖 head drop→SeqGap；未覆盖 Rollback、ResyncLoop、reorder buffer 上限。
5. **F13/F14 注入保真度**：当前用 outbox 容量耗尽/只读 backing 近似 ENOSPC/EIO，不是真实磁盘故障。
6. **F19 failpoint 杀进程**：当前只验证 staging 残留清理，未跑 5 个 JOIN failpoint。
7. **F21/F22 与 45 的偏差**：产品选择 fail-closed；45 仍写“跳过+标记分叉”/“ORDERED 触发全量重同步”。
8. **F24/D10**：fcntl/flock 已覆盖；死锁牺牲者、LEAVE 释放 fcntl 未覆盖；D10 无独立 M2 用例。
9. **F3/F5/F10/F12 子场景**：F3 只跑 2 帧窗口、F5 固定 200ms 无抖动、F10 只回拨、F12 未注入真实时钟回拨。

## 8. 变更规则

- 本目录只写测试配方；不改产品代码、`Cargo.toml`、`src/lib.rs`、CI。
- 新增/修改场景：先改 `scenarios.md` 的行为与断言，再改 `faults.md` 的注入方式，最后才写测试。
- 断言变化必须回写 31/45 的追溯编号；安全断言不能为了通过而放宽。
- 测试名格式：`c_<recipe>_<case>`；当前 M4 用 `f1_...`/`w1_...`/`m4_1_...`，新用例优先 `c_` 前缀。
- 失败最小化：同 seed 重放 → 缩短 recipe → 二分故障规则 → 输出最小复现脚本。
- 连续 3 次 flake → 隔离 + issue + owner + 截止日；不允许静默 skip。
