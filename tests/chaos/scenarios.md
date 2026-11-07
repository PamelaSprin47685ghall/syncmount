# 场景与断言（F1–F24 / R1–R13 / D1–D16 / W1–W7）

本文件回答三件事：注入什么、期望什么、断言什么。注入机制见 `faults.md`；运行方式见 `README.md`。

状态记号：**完整** = 断言已覆盖配方要求；**部分** = 只覆盖主路径，子场景缺失；**缺失** = 尚未实现。状态指当前 `tests/chaos/` 的落地，不是配方本身。

## 1. 断言词汇

安全断言零容忍，任何一次违反即阻塞发版；安全测试不重试。

| ID | 断言 | 判定 |
|---|---|---|
| SAFE-1 | 无静默分叉 | quiescence 时所有 STEADY 客户端 `manifest_root` 相同；不同必须有 resync/unmount/删除事件解释 |
| SAFE-2 | 无撕裂 | op 粒度原子；同偏移终态字节来自单一 op，或可由 seq 全序解释；`applied_seq >= op.seq` 后不得只见部分 op |
| SAFE-3 | 无幽灵 | 路径存在性/内容可由 op log/snapshot 推导；无幽灵会话；用户树无临时文件；内部项不可见 |
| SAFE-4 | 错误 PSK 不进 STEADY | 错误密钥零 op 上行、不挂载、不进入 STEADY；验签失败 fail-closed |
| SAFE-5 | 无静默 seq 空洞 | 缺口必须显式 `SeqGap`/`Rollback`/KICK；重复丢弃；不重发、不静默跳过 |
| SAFE-6 | 无部分应用/无回滚 | AEAD/签名失败零 apply；重放不重复应用；跨 epoch 不比较 applied_seq |
| SAFE-7 | 交换原子 | JOIN staging 交换任一时刻旧树或新树完整；崩溃残留只在 `.syncmount-staging` |
| SAFE-8 | 锁语义正确 | flock 仅本机且不阻塞其他端；fcntl 跨端互斥；F_GETLK 跨端；LEAVE 释放 fcntl；死锁牺牲者确定 |

活性断言（故障消除后）：

| ID | 断言 |
|---|---|
| LIVE-1 | 收敛 p99 < 120s；所有在线客户端达到 quiescence |
| LIVE-2 | 断线检测 ≤ 15s 心跳超时 + 抖动；卸载 < 1s；无 OFFLINE 宽限 |
| LIVE-3 | 无故障对照跑同一操作序列，终态 manifest root 逐字节相同 |
| LIVE-4 | 失败显式：ENOSPC/EIO/EACCES/EEXIST/ENOTEMPTY 等 errno 或 KICK，不静默成功 |

## 2. 负载场景 S1–S10

| ID | 场景 | 负载 |
|---|---|---|
| S1 | 单写者顺序 | 单客户端连续写/改名/删 |
| S2 | 双写者 | 两客户端并发写同文件同偏移或非重叠区间 |
| S3 | 断连-重挂载 | 断网/崩溃后重挂载，cluster-wins |
| S4 | 元数据密集 | chmod/utimens/xattr/mkdir-rmdir 高频 |
| S5 | 大文件 | 100 MiB 分块写，chunk 乱序/重复/丢失敏感 |
| S6 | 多客户端 | 5–10 客户端在线，广播负载与重连风暴 |
| S7 | 加入期间写 | 新节点 JOIN 时 A/B 持续写 |
| S8 | 锁竞争 | flock/fcntl 竞争与死锁环 |
| S9 | 服务器重启 | kill -9 / 正常重启 / 同连接 seq 空间替换 |
| S10 | 时钟偏移 | 客户端 ±1h、服务器运行期/跨重启回拨 |

## 3. F1–F24 故障场景

### 3.1 传输与顺序（F1–F9）

| ID | 故障 | 注入点 | 预期行为 | 断言 | 档 | 当前落地 |
|---|---|---|---|---|---|---|
| F1 | 上行帧丢失（连接不断） | 帧级上行代理丢第 N 帧、中间 chunk、最后一个 op；不关闭 TCP | 丢失 op 永不被定序；客户端回显序倒置 → `Fatal::UplinkLost`；最老未回显超阈值 → `Fatal::UplinkStall`；均 UNMOUNTING(10)，不重发。服务端 T1 水位线 `Stalled` 兜底 | SAFE-1、SAFE-5；oplog 无该 op；丢失 op 不占用 seq；客户端不 STEADY；exit 10 | T | `f1_...` 部分：只覆盖服务端不静默定序 + Stalled，未覆盖 `UplinkLost`/`UplinkStall` |
| F2 | 下行帧丢失 | 帧级下行代理丢第 N 帧（中间/最后）；可选 seq 回退+新 op_id、连续 3 次重同步 | 乱序/缺口进 reorder buffer（≤1024 帧、≤1s）；真缺口 → `Resync::SeqGap` → JOINING；回退（seq≤applied 且 op_id 未见）→ `Resync::Rollback` → JOINING；重复丢弃；连续 3 次重同步且无 ≥60s 稳态 → `ResyncLoop` → exit 10 | SAFE-1、SAFE-2、SAFE-5；无部分应用；resync 原因可观测；终态收敛或卸载 | T/M | `f2_...` 部分：只覆盖 head drop → SeqGap；Rollback/ResyncLoop/buffer 上限缺失 |
| F3 | 乱序 | 帧级下行代理 reorder 窗口 2/10 | 按 seq 缓冲，窗口满后确定性释放；补齐 drain；不触发 resync；终态与有序对照相同 | SAFE-1、SAFE-2、SAFE-3、LIVE-3 | T/M | `f3_...` 部分：2 帧窗口；10 帧未覆盖 |
| F4 | 重复 | 下行复制第 N 帧；上行重复同一 op | 下行按 seq 丢弃；上行按 op_id 去重；不推进两次；无第二次效果 | SAFE-2、SAFE-5 | T/M | `f4_...` 完整 |
| F5 | 延迟/抖动 | 下行 `delay 200ms±100ms`，可 per-connection | 只放慢收敛；无安全违反；故障消除后 p99 < 120s | LIVE-1、LIVE-3 | T/M | `f5_...` + `f5b_...` 部分：固定 200ms，无抖动；30 次 p99 |
| F6 | 断连 FIN/RST | 字节代理 `Close` 或真实 socket close | 立即 UNMOUNTING → exit 10；无 OFFLINE 宽限；server 在线表移除；无幽灵会话 | SAFE-3、LIVE-2 | T/M | `f6_...` 部分：downlink EOF + server clients=0；exit 10 由 W6/M2-8 覆盖 |
| F7 | 半开/黑洞 | 字节代理 `Blackhole`：不读不写、不发 FIN；server tick +16s/+600s | 无 TCP 信号；server 无应用层计时器，不产生 KICK；存活由内核 keepalive（60s/10s/3）判断，真实断网由 transport 错误触发移除与 exit 10 | SAFE-3、LIVE-2 | T/M | `f7_...` 完整（应用代理无法触发内核 keepalive，sockopt 由 P0 单测覆盖） |
| F8 | 服务器重启 | kill -9/正常重启，新 epoch、seq=0；或同连接 seq 空间替换 | 真实重启 → TCP 断 → exit 10 → 重挂载新 epoch → Full resync；同连接替换 → 回退+新 op_id → STEADY→JOINING；不承诺 acked 写持久 | SAFE-1、SAFE-5、LIVE-1 | T/M | `f8_...` 部分：进程重启/新 epoch 完整；同连接替换缺失 |
| F9 | 慢消费者/队列满 | 单客户端下行延迟；outbox `cap_frames=1`、`data_frames=1` | 5s 内有 drain 的溢出只丢当前帧并计数；超过 grace 无 drain → KICK `QueueOverflow`；重连后全量重同步 | SAFE-5、LIVE-1 | T/M | `f9_...` 完整 |

### 3.2 时间与持久化（F10–F14）

| ID | 故障 | 注入点 | 预期行为 | 断言 | 档 | 当前落地 |
|---|---|---|---|---|---|---|
| F10 | 客户端时钟回拨/前跳 | `TestClock` 或 `libfaketime` ±1h | seq 顺序与重放结果不变；mtime 来自载荷；ctime=本地 apply 或 0；manifest 与对照相同 | SAFE-1、SAFE-2、LIVE-3 | T/M | `f10_...` 部分：仅回拨 -3600s，未覆盖前跳 |
| F11 | 服务器运行期时钟回拨 | server `tick` 回拨 1h；PING/HELLO 上报 | 顺序只用 seq；不重排、不误踢；`server_time` 诊断值非降 | SAFE-5、LIVE-1 | T | `f11_...` 完整 |
| F12 | 服务器重启+时钟回拨 | 重启 + 回拨 + 旧 applied_seq 上报 | epoch 变、seq=0；跨 epoch 不比较 applied_seq；Full resync；无回退比较 | SAFE-1、SAFE-5 | T/M | `f12_...` 部分：覆盖 epoch 隔离，未注入真实时钟回拨 |
| F13 | 客户端磁盘满 | `FaultyStore` ENOSPC / `fallocate` 占满 backing；当前用 outbox 容量耗尽 | ENOSPC；失败写不产生 op；无半写；解除后写恢复 | SAFE-2、SAFE-5、LIVE-4 | T/M | `f13_...` 部分：outbox cap，不是真实磁盘 |
| F14 | 本地写盘失败/短写 | `FaultyStore` EIO/ShortWrite；当前用只读 backing | FUSE EIO；失败写不产生 op；已写部分按 POSIX；重挂载 cluster-wins | SAFE-2、SAFE-5、LIVE-4 | T/M | `f14_...` 部分：只读 backing 返回 EACCES，不是 EIO/短写 |

### 3.3 加密、身份、重放与崩溃（F15–F19）

| ID | 故障 | 注入点 | 预期行为 | 断言 | 档 | 当前落地 |
|---|---|---|---|---|---|---|
| F15 | 解密失败 | 下行翻转密文字节或 AEAD tag | 拒绝该帧、不 apply；无部分应用；从最后覆盖 seq 重同步，后续完整帧可应用 | SAFE-2、SAFE-6 | T/M | `f15_...` 完整 |
| F16 | PSK 错误 | 客户端错误 PSK；有验证者在线 | JOIN_PROOF/AUTH 失败 → KICK 或 exit 2；永不 STEADY；零 op 上行；其他端不受影响 | SAFE-4 | T/M | `f16_...` 部分：有验证者完整；空集群首客户端被信任（见 G5） |
| F17 | 重放 | 重放旧 op 帧、旧 HELLO | op_id 幂等丢弃；旧 HELLO → T4 踢旧留新；无回滚、无重复效果 | SAFE-5、SAFE-6 | T/M | `f17_...` 完整 |
| F18 | 客户端 kill -9/进程崩溃 | kill -9 或 abort + force_unmount；重挂载 | auto_unmount；无幽灵会话；重挂载 cluster-wins；不重放；审计计数与实际删除一致 | SAFE-3、SAFE-6、LIVE-1 | T/M | `f18_...` 部分：保留 `no remote view` known-gap 分支 |
| F19 | JOIN staging 崩溃 | staging 残留；5 个 JOIN failpoint 各杀一次 | 旧树或新树完整；staging 清理；用户树无临时文件；`*.sm-tmp` 只在隐藏区 | SAFE-3、SAFE-7 | M | `f19_...` 部分：只验证 cleanup_stale，未跑 5 个 failpoint |

### 3.4 水位线、版本偏斜、签名与锁（F20–F24）

| ID | 故障 | 注入点 | 预期行为 | 断言 | 档 | 当前落地 |
|---|---|---|---|---|---|---|
| F20 | 水位线违例 | 伪造 T2 回退、T3 越界、T4 双开 | 立即 KICK：`Regression`/`Overclaim`/`DuplicateClient`；T4 踢旧留新 reason=3；旧不再收 ORDERED；relay 槽释放 | SAFE-5、LIVE-4 | T/M | `f20_...` 部分：T2/T3/T4；relay 槽由 W4 覆盖 |
| F21 | 未知 op_class | WCP `op_class=0xff` | fail-closed：不 apply、不推进、发 LEAVE 后卸载（39/51/55） | SAFE-1、SAFE-6 | T | `f21_...` 部分：拒绝+零应用；LEAVE/卸载未断言 |
| F22 | 未知 message type | 帧头 type=0x7f | fail-closed：ORDERED 类不推进；控制类忽略/ERROR；连接关闭或 LEAVE | SAFE-5、SAFE-6 | T | `f22_...` 部分：拒绝+seq 不变（可能留 LEAVE pseudo-op）；与 45 的“ORDERED→全量重同步”不一致（见 G7） |
| F23 | 签名伪造/服务器篡改 | 错钥、改 payload hash、跨成员签名、重放 KeyAnnounce、改帧头/AAD | 验签/AEAD fail-closed；不 apply；重放不重复；跨成员伪造拒绝 | SAFE-4、SAFE-6 | T/M | `f23_...` 完整 |
| F24 | 锁语义 | 两客户端 fcntl/flock 竞争；LEAVE；死锁环 | flock 仅本机（B 不被阻塞）；fcntl 跨端互斥（B EAGAIN）；F_GETLK 跨端；LEAVE 释放 fcntl；死锁牺牲者=最小 op_seq | SAFE-8、LIVE-4 | M | `f24_...` 部分：fcntl/flock 完整；死锁/LEAVE 缺失（见 G8） |

### 3.5 F × S 矩阵

T=常规档（N=30）；M=重点档（N=50，含对照）；—=该组合无独立信息量。

| 故障 \ 场景 | S1 | S2 | S3 | S4 | S5 | S6 | S7 | S8 | S9 | S10 |
|---|---|---|---|---|---|---|---|---|---|---|
| F1 上行丢失 | T | T | — | T | — | T | — | — | — | — |
| F2 下行丢失 | T | T | T | T | M | M | M | — | — | — |
| F3 乱序 | — | T | T | — | M | T | M | — | — | — |
| F4 重复 | T | T | T | — | M | T | M | — | — | — |
| F5 延迟 | T | T | T | T | T | M | T | T | — | — |
| F6 断连 | T | T | M | T | T | M | M | T | — | — |
| F7 半开 | T | T | M | T | — | T | — | — | — | — |
| F8 服务器重启 | T | T | T | T | T | M | M | — | M | — |
| F9 慢消费者 | — | M | — | — | — | M | M | — | — | — |
| F10 客户端时钟 | T | T | T | T | — | T | — | — | — | M |
| F11/F12 服务器时钟 | T | T | M | T | — | T | — | — | M | — |
| F13/F14 磁盘 | T | — | — | T | M | — | — | — | — | — |
| F15 密文损坏 | T | T | — | — | M | T | M | — | — | — |
| F16 错误 PSK | T | — | — | — | — | T | — | — | — | — |
| F17 重放 | T | T | — | — | T | T | — | — | — | — |
| F18 崩溃 | T | T | M | T | T | T | M | — | — | — |
| F19 staging 崩溃 | — | — | — | — | — | — | M | — | — | — |
| F20 水位线违例 | T | T | — | — | — | T | — | — | — | — |
| F21/F22 版本偏斜 | T | T | — | T | — | T | — | — | — | — |
| F23 签名伪造/篡改 | T | T | — | T | — | T | — | — | — | — |
| F24 锁语义 | — | T | — | — | — | T | — | M | — | — |

## 4. R1–R13 组合配方

| ID | 名称 | 配方 | 场景 | 主要断言 | 落地 |
|---|---|---|---|---|---|
| R1 | 烂网络 | delay 200ms±100 + loss 1% + dup 0.5%，30min | S2 | 收敛 p99 < 120s；无分叉；对照 root 相同 | 配方 |
| R2 | 半开地狱 | 随机客户端 silent 30s（>15s 心跳），恢复，循环 10 次 | S3 | 每次 <20s 卸载；重挂载收敛；无 pending | 配方 |
| R3 | 重启风暴 | S6 在线，kill -9 server → 立即重启 → 5s 后再 kill | S6/S9 | epoch 变化；所有端 Full resync；重连无 herd | 配方 |
| R4 | 磁盘满时刻 | S5 传输中占满 backing → 解除 | S5 | ENOSPC；失败写无 op；解除后恢复 | 配方 |
| R5 | 时钟错乱日 | 客户端 ±1h + 服务器运行期回拨 + 重启回拨 | S10/S9 | seq 顺序不受时钟影响；重启 seq 重置+epoch；终态 manifest 一致 | 配方 |
| R6 | 密钥混乱 | S6 中一台错误 PSK | S6 | 该端永不 STEADY；零 op；其他端不受影响 | 配方 |
| R7 | 慢消费者 | 单客户端下行 delay 5s，队列堆积 | S6 | KICK；无 seq 空洞；重挂载收敛 | 配方 |
| R8 | 崩溃循环 | 随机 kill -9 客户端，重挂载，重复 | S3/S5 | 不重放；cluster-wins；审计计数 | 配方 |
| R9 | staging 崩溃 | JOIN 在 5 个 failpoint 各杀一次 | S7 | 旧树或新树完整；staging 清理 | 配方 |
| R10 | 水位线违例 | 冻结 apply、回退、越界、双开、空闲、慢速、追平 | S1/S2 | T1/T2/T3/T4 正确；误踢防护零误踢 | 配方 |
| R11 | 上行吞帧 | 代理吞中间 HTTP chunk（保持 TCP）与吞最后一个 op 各一轮 | S1/S2 | 中间 chunk → 下次自发 op 回显立即 Fatal；最后一帧 → 阈值内 Fatal；均 exit 10；不重发 | 配方 |
| R12 | 下行分类 | T-gap、T-shuffle 10 帧、T-rollback、T-resync-loop | S1/S2 | gap → 1s 内 STEADY→JOINING、日志 SeqGap、不退出；shuffle → 零重同步、终态一致；rollback → JOINING；resync-loop → exit 10、日志 ResyncLoop | 配方 |
| R13 | 签名/锁/seq 组合 | 伪造 Ed25519 + 服务器篡改 + flock/fcntl 竞争 + seq 回退 | S2/S6/S8 | 验签 fail-closed；flock 本机不阻塞 B、fcntl 跨端 EAGAIN；seq 回退→JOINING | 配方 |

## 5. D1–D16 映射

D 系列的正确性基线在 I 层；混沌只注入故障。下表给出每个 D 的最小故障集合、对应配方与现有测试。

| D | 场景 | 注入故障 | 配方 | 现有测试/证据 | 关键断言 |
|---|---|---|---|---|---|
| D1 | 同偏移并发写 | F5 延迟、F10 时钟、F18 崩溃 | R1、R5 | `m2_4_same_offset_lww_no_tearing` | 无撕裂；终态字节 ∈ 合法集合；两端相同 |
| D2 | 非重叠并发写 | F3 乱序、F4 重复、F5 延迟 | R1 | `m2_5_non_overlapping_writes_survive` | 两区间都保留；不互相覆盖 |
| D3 | rename vs write | F3、F4、F5 | R1 | `m2_6_rename_unlink_serial_arbitration` | 单一串行顺序；终态一致；无幽灵 |
| D4 | rename vs unlink | F3、F4、F5 | R1 | `m2_6_rename_unlink_serial_arbitration` | 同上；败者 errno 确定 |
| D5 | O_EXCL 竞态 | F5、F6 | R1 | `m2_7_create_excl_exactly_one_wins` | 恰一方成功；败者 EEXIST |
| D6 | 断网卸载-重挂载 | F6、F7、F18 | R2、R8 | `m2_8_remount_cluster_wins`、`m4_1_kill9_...` | 卸载；cluster-wins；本地独有删除；不重放 |
| D7 | 新节点加入 | F5、F13/F14、F19 | R4、R9 | `m3_1_new_node_catches_up_...` | 只传差异；staging 交换；用户树无临时文件 |
| D8 | 服务器重启 epoch | F8、F12 | R3、R5 | `m3_5_...`、`m3_6_...`、`f8_...` | epoch 变；Full resync；不断言 acked 写持久 |
| D9 | 广播丢失/乱序 | F2、F3、F4 | R12 | `m2_9_...`、`m2_10_...`、`f2/f3/f4` | 缺口→JOINING；乱序 buffer；重复丢弃；无静默分叉 |
| D10 | 锁语义 | F24 | R13 | `f24_fcntl_is_cross_client_and_flock_is_local` | SAFE-8：fcntl 跨端 EAGAIN；flock 本机；F_GETLK；LEAVE 释放（LEAVE/死锁子项见 G8） |
| D11 | rmdir vs 远端写 | F5、F6 | R1 | `m4_9_rmdir_race_...` | 终态一致；rmdir 失败显式 ENOTEMPTY/ENOENT |
| D12 | unlink→create | F4、F17 | R12 | `m4_8_unlink_then_create_...` | 新文件赢；旧 fd 读旧 inode；两端一致 |
| D13 | 大文件分块乱序/重复 | F2、F3、F4、F15 | R12 | `m3_7_staging_out_of_order_duplicate_segments`、`m3_7_chunk_layer_out_of_order_open` | 100 MiB hash 一致；乱序/重复可组装；不 OOM |
| D14 | 时钟偏移免疫 | F10、F11、F12 | R5 | `f10_...`、M4-3 | seq 顺序不变；结果与对照逐字节相同 |
| D15 | fsync 跨端可见性 | F14、F18 | R8 | `m4_6_fsync_is_local_only_...` | 本地 fsync 后 kill 数据在；集群可见性不承诺；重挂载 cluster-wins |
| D16 | 类型冲突 | F5 | R1 | `m4_7_type_conflict_...` | 终态类型唯一；后到 EEXIST；两端一致 |

## 6. W1–W7 映射

| W | 触发/注入 | 预期与断言 | 配方 | 测试 | 31 映射 |
|---|---|---|---|---|---|
| W1 | 每次 HELLO/PING 上报 applied_seq；ctrl_prefix 18B；`reserved` 校验；最近 60 样本 nearest-rank P99；backlog=QueueStats.bytes；applied_seq 单调 | 每次上报都被校验并记录；非法 reserved 拒绝；未知 RTT 退化 300ms；不得 60s floor | F20、F5 | `w1_...`、`w1_http_ping_...` | M4-10 |
| W2 | 停滞诊断：`3×RTT_p99 + backlog/1MiBps + pending_ops×100ms`，上限 24h；1s tick；busy=`current_seq>applied_seq` | 超阈值只产生诊断（日志 + `watermark_lag_ms`/`pending_ops` 指标），不踢人；阈值随 pending/backlog 增长 | F5、F9 | `w2_...` | M4-11 |
| W3 | 空闲无上报：10min 无 PING | 不踢出；会话保持 STEADY；连接与内核 keepalive 判断存活 | F7 | `w3_...` | M4-12 |
| W4 | T2 回退 / T3 越界 / T4 双开 | T2/T3 立即 KICK；T4 踢旧留新 reason=3；旧不再收 ORDERED；relay 槽释放 | F20、F17 | `w4_...` | M4-13 |
| W5 | 误踢防护：空闲 10min、慢盘/慢网在阈值内、积压追平中 | 零误踢；busy 门正确；阈值随实测自适应（RTT 项当前 300ms fallback，见 G9） | F5、F9 | `w5_...` | M4-14 |
| W6 | 踢出后自动卸载 | 进程 exit 10；`/proc/mounts` 无残留；无僵尸 | F20、F6 | `w6_...` | M4-15 |
| W7 | 踢出/断线后重挂载 | cluster-wins Full resync；`diff -r` 为空；审计计数正确 | F18、F6 | `w7_...` | M4-16 |

W1 当前为 known_gap：`ctrl_prefix.reserved` 固定 0，RTT 永不上报，T1 网络项固定 300ms fallback。W1b 是线上 PING 的补充断言。

## 7. 覆盖缺口与未决

| # | 缺口 | 影响 | 处置 |
|---|---|---|---|
| G1 | F1 只覆盖服务端“不静默定序 + Stalled”，未覆盖客户端 `UplinkLost`/`UplinkStall` | 45 C6/INV-22 的核心检测路径未验证 | 增加 F1a（吞中间 chunk，回显序倒置）与 F1b（吞最后一帧，最老未回显超时），均断言 exit 10、不重发 |
| G2 | F2 只覆盖 head drop→SeqGap；未覆盖 Rollback、ResyncLoop、reorder buffer 1s/1024 帧上限 | seq 四分只验证了一分 | 增加 R12 的 T-rollback、T-resync-loop、T-shuffle 10 帧；断言 JOINING 原因与预算 |
| G3 | F8 只覆盖真实进程重启/新 epoch；同连接 seq 空间替换未覆盖 | `RestartMode::ReplaceSeqSpace` 路径未验证 | 增加同连接回退+新 op_id 注入，断言 STEADY→JOINING |
| G4 | F13/F14 用 outbox 容量耗尽/只读 backing 近似 ENOSPC/EIO | 真实磁盘错误路径未验证 | 增加 `FaultyStore`（Eio/Enospc/ShortWrite/Delay）或 LD_PRELOAD；断言失败写零 op、短写按 POSIX |
| G5 | F16 空集群首客户端被信任，错误 PSK 可加入空集群 | SAFE-4 边界缺口，安全严重度高 | 产品裁决：空集群首客户端是否也必须通过 PSK proof；若必须，F16 增加空集群错误 PSK 用例 |
| G6 | F18 测试保留 `no remote view` known-gap 分支 | BUG-2 修复后仍可能掩盖回归 | 稳定后删除容错分支，改为硬断言 remount=ok |
| G7 | F21/F22 与 45 不一致：45 写“跳过+标记分叉”/“ORDERED→全量重同步”，产品 fail-closed | 文档与实现冲突 | 协议 owner 裁决并回写 39/45；测试按裁决断言 LEAVE/卸载或全量重同步 |
| G8 | F24 未覆盖死锁牺牲者、LEAVE 释放 fcntl；D10 无独立 M2 用例 | 锁语义只覆盖主路径 | 增加 S8 死锁环（牺牲者=最小 op_seq）与 LEAVE 释放；补 D10 定向用例 |
| G9 | W1/W1b RTT 未上报，`reserved=0`，T1 固定 300ms fallback | 动态阈值不能按实测 RTT 自适应；与 45 W1 冲突 | 裁决是否解冻 ctrl_prefix 的 `reserved`；解冻前 known_gap 保留 |
| G10 | F19 未跑 5 个 JOIN failpoint 杀进程 | staging 交换原子性只验证了清理路径 | 用 `join_after_manifest`、`join_after_stage_fsync`、`join_before_rename1/2/3` 各杀一次 |
| G11 | F5b p99 是 30 次进程内重放，不是全集群收敛 | 活性断言覆盖面窄 | 在 R1/R7 中用真实多客户端 quiesce 采样 p99 |
| G12 | M4-2 验收要求 30min，记录运行缩短为 180s | 长跑 soak 未进默认门禁 | 发布前跑 `SM_M4_SOAK_SECS=1800`，记录入 summary |
| G13 | F3/F5/F10/F12 只覆盖主路径：F3 用 2 帧窗口、F5 固定 200ms 无抖动、F10 只回拨、F12 未注入真实时钟回拨 | 配方子场景未全跑 | 按 F 表补 10 帧 reorder、200±100ms、前跳、真实回拨；安全断言不变 |

需要用户/主代理裁决的项：G5（空集群 PSK）、G7（F21/F22 口径）、G9（RTT 上报）；其余为实现/测试 owner 可自行推进。

## 附录 A：当前测试名（定位用）

名称只用于定位当前落地；配方以行为与断言为准，替换实现不必保留命名。

| ID | 测试路径（`chaos::` 前缀省略） |
|---|---|
| F1 | `faults::f1_uplink_loss_is_never_silently_sequenced` |
| F2 | `faults::f2_downlink_loss_is_detected_as_a_seq_gap` |
| F3 | `faults::f3_reorder_buffers_and_converges_to_the_same_tree` |
| F4 | `faults::f4_duplicate_frames_and_ops_are_idempotent` |
| F5 | `faults::f5_delay_slows_convergence_without_changing_the_tree` |
| F5b | `faults::f5b_convergence_p99_is_below_120s` |
| F6 | `faults::f6_disconnect_ends_the_downlink_and_removes_the_session` |
| F7 | `faults::f7_half_open_link_is_not_evicted_by_an_application_timer` |
| F8 | `faults::f8_server_restart_changes_epoch_and_forces_a_full_resync` |
| F9 | `faults::f9_queue_overflow_kicks_only_a_queue_that_stopped_draining` |
| F10 | `faults::f10_client_clock_rollback_does_not_change_the_replay_result` |
| F11 | `faults::f11_server_clock_rollback_does_not_reorder_or_kick` |
| F12 | `faults::f12_restart_with_a_clock_rollback_is_epoch_scoped` |
| F13 | `faults::f13_disk_full_returns_enospc_and_enqueues_no_op` |
| F14 | `faults::f14_local_write_failure_returns_eacces_and_enqueues_no_op` |
| F15 | `faults::f15_corrupt_ciphertext_never_partially_applies` |
| F16 | `faults::f16_wrong_psk_is_rejected_by_a_join_proof` |
| F17 | `faults::f17_replayed_frames_and_hellos_have_no_rollback_effect` |
| F18 | `faults::f18_abrupt_loss_leaves_no_ghost_and_remount_reports_cluster_wins` |
| F19 | `faults::f19_staging_residue_is_cleaned_and_the_user_tree_is_complete` |
| F20 | `faults::f20_watermark_violations_kick_immediately` |
| F21 | `faults::f21_unknown_op_class_fails_closed` |
| F22 | `faults::f22_unknown_message_type_fails_closed` |
| F23 | `faults::f23_forged_signatures_and_tampered_envelopes_fail_closed` |
| F24 | `faults::f24_fcntl_is_cross_client_and_flock_is_local` |

| ID | 测试路径（`chaos::` 前缀省略） |
|---|---|
| W1 | `watermark::w1_reports_are_18_bytes_and_every_report_is_checked` |
| W1b | `watermark::w1_http_ping_is_validated_on_the_wire` |
| W2 | `watermark::w2_dynamic_threshold_prices_pending_ops_and_backlog` |
| W3 | `watermark::w3_idle_session_without_a_ping_is_not_evicted` |
| W4 | `watermark::w4_duplicate_client_id_kicks_the_old_session` |
| W5 | `watermark::w5_idle_slow_and_backlog_do_not_kick` |
| W6 | `watermark::w6_kick_unmounts_and_exits_10` |
| W7 | `watermark::w7_remount_after_kick_is_cluster_wins_full_resync` |
